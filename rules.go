package main

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// User rules: persistent, hand-editable annotations on remote addresses.
//
//   - alias: "this address (or range) is <name>" — 160.79.104.10 → Anthropic.
//     Aliases are how you teach porthawk about hosts reverse DNS and RDAP
//     can't name, and they win over both.
//   - hide: "I don't care about this traffic" — matched rows are flagged,
//     not dropped, so the UI can reveal them again instantly and tell you
//     how many are hidden.
//   - exclude: the same idea narrowed to one question — "stop showing me
//     anything owned by this organisation". It matches only the ownership
//     name, never a hostname or an address, so excluding "Cloudflare"
//     cannot accidentally catch a host that merely has the word in its
//     PTR record. Kept as its own list because it is the one people edit
//     often, and it deserves a place in the settings panel rather than a
//     hand-typed term in the filter box. Entries can be switched off
//     without being deleted.
//
// Both are evaluated server-side (one source of truth, survives reloads and
// other browsers) but *applied* client-side from the flags on each row, so
// the on/off toggles are instant and need no round trip.
//
// Stored as ~/.config/porthawk/rules.json — plain, ordered, hand-editable:
//
//	{
//	  "aliases": [{"match": "160.79.104.0/21", "name": "Anthropic"}],
//	  "hidden":  [{"match": "Anthropic"}, {"match": "10.0.0.0/8"}]
//	}
type Rules struct {
	mu       sync.RWMutex
	path     string
	aliases  []Rule
	hidden   []Rule
	excluded []Rule

	// parsed forms of the above, rebuilt on every change so matching does
	// no parsing per connection per tick
	aliasNets []netRule
	aliasStrs []strRule
	hideNets  []netip.Prefix
	hideStrs  []string
	exclStrs  []string
}

// Rule is one stored rule. Match is an IP, a CIDR, or a plain name; Name is
// the alias to display (unused for hide rules). Off keeps a rule in the
// list but stops it matching, so a rule can be parked without losing it —
// retyping an owner name to get it back is exactly the friction that makes
// people stop curating the list.
type Rule struct {
	Match string `json:"match"`
	Name  string `json:"name,omitempty"`
	Off   bool   `json:"off,omitempty"`
}

type netRule struct {
	pfx  netip.Prefix
	name string
}

type strRule struct {
	sub  string // lowercased substring
	name string
}

type rulesFile struct {
	Aliases  []Rule `json:"aliases"`
	Hidden   []Rule `json:"hidden"`
	Excluded []Rule `json:"excluded"`
}

func NewRules(cfgDir string) *Rules {
	r := &Rules{path: filepath.Join(cfgDir, "rules.json")}
	r.load()
	return r
}

func (r *Rules) load() {
	var f rulesFile
	if b, err := os.ReadFile(r.path); err == nil {
		// A corrupt file must not lose the user's other settings or stop
		// the app: ignore it and start empty.
		_ = json.Unmarshal(b, &f)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aliases, r.hidden, r.excluded = f.Aliases, f.Hidden, f.Excluded
	r.compileLocked()
}

// compileLocked rebuilds the matching forms. Caller holds the write lock.
func (r *Rules) compileLocked() {
	r.aliasNets, r.aliasStrs = r.aliasNets[:0], r.aliasStrs[:0]
	r.hideNets, r.hideStrs = r.hideNets[:0], r.hideStrs[:0]
	r.exclStrs = r.exclStrs[:0]
	for _, a := range r.aliases {
		if a.Name == "" || a.Off {
			continue
		}
		if p, ok := parseTarget(a.Match); ok {
			r.aliasNets = append(r.aliasNets, netRule{p, a.Name})
		} else if s := strings.ToLower(strings.TrimSpace(a.Match)); s != "" {
			r.aliasStrs = append(r.aliasStrs, strRule{s, a.Name})
		}
	}
	for _, h := range r.hidden {
		if h.Off {
			continue
		}
		if p, ok := parseTarget(h.Match); ok {
			r.hideNets = append(r.hideNets, p)
		} else if s := strings.ToLower(strings.TrimSpace(h.Match)); s != "" {
			r.hideStrs = append(r.hideStrs, s)
		}
	}
	// Owner exclusions are names only — an owner is never a CIDR, and
	// treating one as an address here would silently create a rule that
	// matches nothing.
	for _, e := range r.excluded {
		if e.Off {
			continue
		}
		if s := strings.ToLower(strings.TrimSpace(e.Match)); s != "" {
			r.exclStrs = append(r.exclStrs, s)
		}
	}
}

// parseTarget reads a rule target as a network: "1.2.3.4" becomes a /32,
// "1.2.3.0/24" stays as written. Anything else is a name pattern.
func parseTarget(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// AliasFor returns the alias an IP/CIDR rule gives this address, or "" if
// none does. It deliberately ignores the name-substring rules, because the
// point of this call is to run *before* the lookups: an address the user has
// already named needs no reverse DNS and no RDAP, while a substring rule
// can only match names those lookups have yet to produce.
func (r *Rules) AliasFor(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.aliasNetLocked(ip)
}

// aliasNetLocked returns the IP/CIDR alias for ip. Most specific network
// wins: a /32 for one host overrides the /21 alias covering its whole
// range. Caller holds the read lock.
func (r *Rules) aliasNetLocked(ip netip.Addr) string {
	best, name := -1, ""
	for _, n := range r.aliasNets {
		if n.pfx.Contains(ip) && n.pfx.Bits() > best {
			best, name = n.pfx.Bits(), n.name
		}
	}
	return name
}

// Apply annotates a connection with its alias and hidden flags.
//
// Both ends get aliased: the local address is an address like any other, and
// aliasing it is the only way to name a LAN host reverse DNS won't.
//
// Name rules match against every name the row can be known by — alias,
// owner, reverse-DNS host, and the raw IP — so hiding "anthropic" catches
// the row whether it is currently displaying an alias, an RDAP owner, or a
// hostname, and regardless of which display toggles happen to be on.
func (r *Rules) Apply(c *Conn) {
	ip, err := netip.ParseAddr(c.RAddr)
	hasIP := err == nil
	lip, lerr := netip.ParseAddr(c.LAddr)
	hasLIP := lerr == nil
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Recomputed, not accumulated: Apply also runs over ghost rows, which
	// are frozen copies carrying whatever was true when the socket died.
	// Without this, deleting a rule leaves it in force on those rows until
	// they expire.
	c.Hide = false

	if hasIP {
		if n := r.aliasNetLocked(ip); n != "" {
			c.Alias = n
		}
	}
	if c.Alias == "" {
		for _, s := range r.aliasStrs {
			if matchesName(s.sub, c.Owner, c.Host, c.RAddr) {
				c.Alias = s.name
				break
			}
		}
	}
	if hasLIP {
		if n := r.aliasNetLocked(lip); n != "" {
			c.LAlias = n
		}
	}
	if c.LAlias == "" {
		for _, s := range r.aliasStrs {
			if matchesName(s.sub, c.LOwner, c.LHost, c.LAddr) {
				c.LAlias = s.name
				break
			}
		}
	}

	if hasIP {
		for _, p := range r.hideNets {
			if p.Contains(ip) {
				c.Hide = true
				return
			}
		}
	}
	for _, s := range r.hideStrs {
		if matchesName(s, c.Alias, c.Owner, c.Host, c.RAddr) {
			c.Hide = true
			return
		}
	}
	// Ownership only. Deliberately not checked against Host or RAddr: an
	// exclusion is a statement about who runs the address, and matching a
	// hostname that happens to contain the word would surprise.
	for _, s := range r.exclStrs {
		if matchesName(s, c.Owner, c.LOwner) {
			c.Hide = true
			return
		}
	}
}

// matchesName reports whether the lowercased needle appears in any of the
// names a row can be displayed under.
func matchesName(needle string, names ...string) bool {
	for _, n := range names {
		if n != "" && strings.Contains(strings.ToLower(n), needle) {
			return true
		}
	}
	return false
}

// ---- mutation ----

// Set adds or replaces an alias. An empty name deletes the rule.
func (r *Rules) Set(match, name string) {
	match, name = strings.TrimSpace(match), strings.TrimSpace(name)
	if match == "" {
		return
	}
	r.mu.Lock()
	r.aliases = replace(r.aliases, match, name)
	r.compileLocked()
	r.mu.Unlock()
	r.save()
}

// Hide adds (on) or removes (off) a hide rule for a target.
func (r *Rules) Hide(match string, on bool) {
	match = strings.TrimSpace(match)
	if match == "" {
		return
	}
	r.mu.Lock()
	if on {
		r.hidden = replace(r.hidden, match, "hidden")
	} else {
		r.hidden = replace(r.hidden, match, "")
	}
	r.compileLocked()
	r.mu.Unlock()
	r.save()
}

// Exclude adds (on) or removes (off) an owner exclusion.
func (r *Rules) Exclude(match string, on bool) {
	match = strings.TrimSpace(match)
	if match == "" {
		return
	}
	r.mu.Lock()
	if on {
		r.excluded = replace(r.excluded, match, "excluded")
	} else {
		r.excluded = replace(r.excluded, match, "")
	}
	r.compileLocked()
	r.mu.Unlock()
	r.save()
}

// ExcludeOff parks or revives an exclusion without deleting it.
func (r *Rules) ExcludeOff(match string, off bool) {
	match = strings.TrimSpace(match)
	if match == "" {
		return
	}
	r.mu.Lock()
	for i := range r.excluded {
		if strings.EqualFold(r.excluded[i].Match, match) {
			r.excluded[i].Off = off
		}
	}
	r.compileLocked()
	r.mu.Unlock()
	r.save()
}

// replace sets match->name in the list, removing the entry when name is
// empty. Matching is case-insensitive so "Anthropic" and "anthropic" are
// the same rule rather than two.
func replace(list []Rule, match, name string) []Rule {
	out := list[:0]
	for _, e := range list {
		if !strings.EqualFold(e.Match, match) {
			out = append(out, e)
		}
	}
	if name != "" {
		out = append(out, Rule{Match: match, Name: name})
	}
	return out
}

// save writes rules.json atomically: a torn write here would lose every
// alias the user has built up.
func (r *Rules) save() {
	r.mu.RLock()
	f := rulesFile{Aliases: r.aliases, Hidden: r.hidden, Excluded: r.excluded}
	path := r.path
	r.mu.RUnlock()

	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

// Snapshot returns a copy of the rules for shipping to the UI.
func (r *Rules) Snapshot() rulesFile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f := rulesFile{
		Aliases:  append([]Rule(nil), r.aliases...),
		Hidden:   append([]Rule(nil), r.hidden...),
		Excluded: append([]Rule(nil), r.excluded...),
	}
	if f.Aliases == nil {
		f.Aliases = []Rule{}
	}
	if f.Hidden == nil {
		f.Hidden = []Rule{}
	}
	if f.Excluded == nil {
		f.Excluded = []Rule{}
	}
	return f
}

// ---- API ----

// handleRules serves the rule list (GET) and edits it (POST).
//
// POST body: {"op": "...", "match": "...", "name": "..."} where op is one of
// alias, unalias, hide, unhide, exclude, unexclude, exclude-off, exclude-on.
func (s *server) handleRules(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.rules.Snapshot())
	case http.MethodPost:
		var body struct {
			Op    string `json:"op"`
			Match string `json:"match"`
			Name  string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Names are displayed as text in the UI; keep them short and
		// single-line so a rule can't wreck the table layout.
		body.Name = strings.TrimSpace(strings.Map(sanitizeRune, body.Name))
		if len([]rune(body.Name)) > 40 {
			body.Name = string([]rune(body.Name)[:40])
		}
		switch body.Op {
		case "alias":
			if body.Name == "" {
				http.Error(w, "alias needs a name", http.StatusBadRequest)
				return
			}
			s.rules.Set(body.Match, body.Name)
		case "unalias":
			s.rules.Set(body.Match, "")
		case "hide":
			s.rules.Hide(body.Match, true)
		case "unhide":
			s.rules.Hide(body.Match, false)
		case "exclude":
			s.rules.Exclude(body.Match, true)
		case "unexclude":
			s.rules.Exclude(body.Match, false)
		case "exclude-off":
			s.rules.ExcludeOff(body.Match, true)
		case "exclude-on":
			s.rules.ExcludeOff(body.Match, false)
		default:
			http.Error(w, "unknown op", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.rules.Snapshot())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// sanitizeRune drops control characters from user-supplied names.
func sanitizeRune(r rune) rune {
	if r < 0x20 || r == 0x7f {
		return -1
	}
	return r
}
