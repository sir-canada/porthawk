package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Owner does cached, toggleable IP-ownership lookups server-side, via Team
// Cymru's IP-to-ASN DNS service (origin.asn.cymru.com). That service is
// free, explicitly intended for exactly this kind of recurring per-address
// query, and — being DNS — its answers are cached by the local resolver as
// well as by us.
//
// The obvious alternative, RDAP over HTTP, is not usable here: the rdap.org
// redirector is rate-limited to 10 requests per 10 seconds and its own
// documentation tells regular clients to go elsewhere. A connection table
// routinely holds more unresolved addresses than that in a single tick, so
// RDAP would spend most of its life being throttled.
//
// Results are cached per BGP prefix, not per IP: one answer names every
// address in the announced range.
type Owner struct {
	enabled atomic.Bool
	mu      sync.Mutex
	cache   map[netip.Prefix]ownerEntry // netip.Prefix is comparable, so no
	order   []netip.Prefix              // string keys in the per-tick hot path
	asn     map[uint32]string           // AS number -> description
	queue   chan string
	queued  map[string]bool
	dir     string
	dirty   bool
}

// ownerEntry carries its own expiry rather than a shared TTL, because the
// reasons for having no name expire at different rates: a network that
// announces no origin AS is worth remembering for a while, but a DNS
// timeout means nothing at all and must not masquerade as "no owner".
type ownerEntry struct {
	name string // "" = negative result
	exp  time.Time
}

// diskEntry is the on-disk shape; the file is a JSON object keyed by
// prefix so it round-trips through load without extra bookkeeping.
type diskEntry struct {
	Name string `json:"name"`
	Exp  int64  `json:"exp"`
}

const (
	// Cymru rebuilds from BGP every 4 hours; a day-old answer is plenty
	// fresh for a label, and the local resolver absorbs the repeats.
	ownerTTL = 24 * time.Hour
	// No origin AS: real, but worth re-checking sooner than a name.
	ownerNegTTL = time.Hour
	// Timeout/SERVFAIL: not an answer. Retry soon, but not every tick.
	ownerFailTTL    = 5 * time.Minute
	ownerFlushEvery = 5 * time.Minute
	ownerNameMax    = 40 // runes
	// Paced for the *local* resolver's benefit, not Cymru's: a cold start
	// has dozens of addresses to name at once, and firing them off as fast
	// as the workers allow makes a stub resolver drop UDP answers, which
	// then look like failures. Five queries a second fills a cold cache in
	// a few seconds and is invisible thereafter.
	ownerMinInterval = 200 * time.Millisecond
	ownerQueryTO     = 5 * time.Second
)

// Outbound queries are paced process-wide rather than per worker. DNS is
// cheap and Cymru publishes no limit, so this is politeness, not throttling.
var (
	ownerRateMu   sync.Mutex
	ownerLastReq  time.Time
	ownerResolver = &net.Resolver{}
	ownerFileName = "owners.json"
)

func NewOwner(cfgDir string, enabled bool) *Owner {
	o := &Owner{
		cache:  make(map[netip.Prefix]ownerEntry),
		asn:    make(map[uint32]string),
		queue:  make(chan string, 1024),
		queued: make(map[string]bool),
		dir:    cfgDir,
	}
	o.enabled.Store(enabled)
	o.load()
	return o
}

func (o *Owner) Start(ctx context.Context) {
	for i := 0; i < 4; i++ {
		go o.worker(ctx)
	}
	go o.flusher(ctx)
}

func (o *Owner) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-o.queue:
			pfx, name, ttl := o.query(ctx, ip)
			o.mu.Lock()
			if pfx.IsValid() && ttl > 0 {
				o.put(pfx, name, ttl)
			}
			delete(o.queued, ip)
			o.mu.Unlock()
		}
	}
}

// flusher persists the cache periodically and once more on shutdown, so
// a restart doesn't re-query ranges we already paid for.
func (o *Owner) flusher(ctx context.Context) {
	t := time.NewTicker(ownerFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			o.Flush()
			return
		case <-t.C:
			o.Flush()
		}
	}
}

// Lookup returns the cached owner name ("" if none) and, when enabled,
// enqueues addresses with no live cache entry. Never blocks.
func (o *Owner) Lookup(ip string) string {
	a, ok := ownerAddr(ip)
	if !ok {
		return ""
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if e, _, ok := o.find(a); ok {
		return e.name
	}
	if o.enabled.Load() && !o.queued[ip] {
		select {
		case o.queue <- ip:
			o.queued[ip] = true
		default: // queue full, retry next tick
		}
	}
	return ""
}

// Prefix returns the CIDR of the owning range ("" if unknown). It never
// enqueues: it only reports what Lookup already discovered.
func (o *Owner) Prefix(ip string) string {
	a, ok := ownerAddr(ip)
	if !ok {
		return ""
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if e, p, ok := o.find(a); ok && e.name != "" {
		return p.String()
	}
	return ""
}

func (o *Owner) SetEnabled(v bool) { o.enabled.Store(v) }
func (o *Owner) Enabled() bool     { return o.enabled.Load() }

// find returns the best unexpired entry containing a: a known owner always
// beats a negative result (a failed probe must not shadow the range whose
// owner we already know), and among equals the most specific prefix wins.
// Caller holds o.mu.
func (o *Owner) find(a netip.Addr) (ownerEntry, netip.Prefix, bool) {
	var best netip.Prefix
	var bestE ownerEntry
	found := false
	now := time.Now()
	for _, p := range o.order {
		if !p.Contains(a) {
			continue
		}
		e, ok := o.cache[p]
		if !ok || now.After(e.exp) {
			continue
		}
		better := !found ||
			(e.name != "" && bestE.name == "") ||
			(e.name != "" == (bestE.name != "") && p.Bits() > best.Bits())
		if better {
			best, bestE, found = p, e, true
		}
	}
	return bestE, best, found
}

// put records an entry, keeping order in sync with cache.
// Caller holds o.mu.
func (o *Owner) put(p netip.Prefix, name string, ttl time.Duration) {
	if _, ok := o.cache[p]; !ok {
		o.order = append(o.order, p)
	}
	o.cache[p] = ownerEntry{name, time.Now().Add(ttl)}
	o.dirty = true
}

// ownerAddr parses ip and reports whether it can have a public owner.
// Addresses that cannot are never cached and never queried.
func ownerAddr(ip string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return netip.Addr{}, false
	}
	return a, true
}

// ownerNetKey is the /24 (v4) or /48 (v6) containing a, used to record a
// result when the answer carries no prefix of its own.
func ownerNetKey(a netip.Addr) netip.Prefix {
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// query performs one origin lookup plus (usually cached) one AS-description
// lookup. It returns the prefix to cache under, the name ("" = negative),
// and the TTL to cache it for — a zero TTL means "learned nothing, don't
// record anything".
func (o *Owner) query(ctx context.Context, ip string) (netip.Prefix, string, time.Duration) {
	a, ok := ownerAddr(ip)
	if !ok {
		return netip.Prefix{}, "", 0
	}
	if err := ownerRateWait(ctx); err != nil {
		return netip.Prefix{}, "", 0 // shutting down
	}
	txts, err := o.txt(ctx, cymruOriginName(a))
	if err != nil {
		if dnsIsNotFound(err) {
			// Authoritative: nothing announces this address.
			return ownerNetKey(a), "", ownerNegTTL
		}
		return ownerNetKey(a), "", ownerFailTTL
	}
	pfx, asn, ok := parseCymruOrigin(txts, a)
	if !ok {
		return ownerNetKey(a), "", ownerNegTTL
	}

	name := o.asnName(ctx, asn)
	if name == "" {
		// Prefix is real even when the description isn't; record it so the
		// range is known, but let it expire soon in case the AS lookup was
		// merely unlucky.
		return pfx, "", ownerFailTTL
	}
	return pfx, name, ownerTTL
}

// asnName resolves an AS number to its description, memoised for the
// process: a handful of networks account for most connections, so this is
// nearly always a map hit.
func (o *Owner) asnName(ctx context.Context, asn uint32) string {
	o.mu.Lock()
	n, ok := o.asn[asn]
	o.mu.Unlock()
	if ok {
		return n
	}
	if err := ownerRateWait(ctx); err != nil {
		return ""
	}
	txts, err := o.txt(ctx, "AS"+strconv.FormatUint(uint64(asn), 10)+".asn.cymru.com")
	if err != nil || len(txts) == 0 {
		return ""
	}
	name := parseCymruASName(txts[0])
	if name == "" {
		return ""
	}
	o.mu.Lock()
	o.asn[asn] = name
	o.mu.Unlock()
	return name
}

func (o *Owner) txt(ctx context.Context, name string) ([]string, error) {
	qctx, cancel := context.WithTimeout(ctx, ownerQueryTO)
	defer cancel()
	return ownerResolver.LookupTXT(qctx, name)
}

// dnsIsNotFound reports whether the error means "this name does not exist"
// rather than "the lookup failed".
func dnsIsNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// ownerRateWait paces outbound queries. The lock is held across the wait so
// the workers queue up behind each other instead of bursting.
func ownerRateWait(ctx context.Context) error {
	ownerRateMu.Lock()
	defer ownerRateMu.Unlock()
	if d := time.Until(ownerLastReq.Add(ownerMinInterval)); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	ownerLastReq = time.Now()
	return nil
}

// --- Cymru DNS parsing --------------------------------------------------

// cymruOriginName builds the query name: reversed octets under
// origin.asn.cymru.com for v4, reversed nibbles under origin6 for v6 (the
// same construction as a reverse-DNS name, different zone).
func cymruOriginName(a netip.Addr) string {
	if a.Is4() {
		b := a.As4()
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
			strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) +
			".origin.asn.cymru.com"
	}
	const hex = "0123456789abcdef"
	b := a.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("origin6.asn.cymru.com")
	return sb.String()
}

// parseCymruOrigin reads answers of the form
//
//	"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
//
// An address can be covered by several announcements (multi-homing, or a
// more specific route inside a larger one); the most specific prefix that
// actually contains the address wins, which is the one traffic follows.
func parseCymruOrigin(txts []string, a netip.Addr) (netip.Prefix, uint32, bool) {
	var best netip.Prefix
	var bestASN uint32
	found := false
	for _, t := range txts {
		f := strings.Split(t, "|")
		if len(f) < 2 {
			continue
		}
		// The AS field may list several origins ("1234 5678") when a prefix
		// is announced by more than one; the first is as good as any.
		asnField := strings.Fields(strings.TrimSpace(f[0]))
		if len(asnField) == 0 {
			continue
		}
		n, err := strconv.ParseUint(asnField[0], 10, 32)
		if err != nil {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(f[1]))
		if err != nil || !p.Contains(a) {
			continue
		}
		if !found || p.Bits() > best.Bits() {
			best, bestASN, found = p, uint32(n), true
		}
	}
	return best, bestASN, found
}

// parseCymruASName reads an answer of the form
//
//	"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
//
// and returns the human part. The description is conventionally
// "<handle> - <organisation>, <CC>", so the organisation is preferred over
// the handle, and the trailing country code is dropped — "Anthropic, PBC"
// rather than "ANTHROPIC - Anthropic, PBC, US".
func parseCymruASName(txt string) string {
	f := strings.Split(txt, "|")
	if len(f) == 0 {
		return ""
	}
	desc := strings.TrimSpace(f[len(f)-1])
	if desc == "" {
		return ""
	}
	if i := strings.Index(desc, " - "); i >= 0 {
		if org := strings.TrimSpace(desc[i+3:]); org != "" {
			desc = org
		}
	}
	// Strip a trailing ", XX" country code, but never mistake a two-letter
	// word that is part of the name for one: only the final comma counts.
	if i := strings.LastIndex(desc, ","); i > 0 {
		if cc := strings.TrimSpace(desc[i+1:]); len(cc) == 2 && isUpperAlpha(cc) {
			desc = strings.TrimSpace(desc[:i])
		}
	}
	return capRunes(desc, ownerNameMax)
}

func isUpperAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

func capRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// --- persistence --------------------------------------------------------

// load restores the cache from disk. A missing or corrupt file is not an
// error: we just start cold. Entries that are already expired (including
// those written by an older format) are simply dropped.
func (o *Owner) load() {
	if o.dir == "" {
		return
	}
	b, err := os.ReadFile(filepath.Join(o.dir, ownerFileName))
	if err != nil {
		return
	}
	var m map[string]diskEntry
	if json.Unmarshal(b, &m) != nil {
		return
	}
	now := time.Now()
	for k, v := range m {
		p, err := netip.ParsePrefix(k)
		if err != nil {
			continue
		}
		exp := time.Unix(v.Exp, 0)
		if v.Exp == 0 || now.After(exp) {
			continue
		}
		o.cache[p] = ownerEntry{v.Name, exp}
		o.order = append(o.order, p)
	}
}

// Flush writes the cache to disk atomically. It is a no-op when nothing
// changed since the last write, so the 5-minute ticker is nearly free.
func (o *Owner) Flush() {
	o.mu.Lock()
	if o.dir == "" || !o.dirty {
		o.mu.Unlock()
		return
	}
	m := make(map[string]diskEntry, len(o.cache))
	for k, e := range o.cache {
		m[k.String()] = diskEntry{Name: e.name, Exp: e.exp.Unix()}
	}
	o.dirty = false
	o.mu.Unlock()

	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	// Same-directory temp + rename so a crash mid-write can't truncate
	// the existing cache.
	tmp := filepath.Join(o.dir, ownerFileName+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, filepath.Join(o.dir, ownerFileName)); err != nil {
		os.Remove(tmp)
	}
}
