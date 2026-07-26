package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Built for the host architecture: the program reads kernel structs
// through a vmlinux.h dumped from the running kernel, and the register
// macros a kprobe needs are per-architecture. Regenerate on the target
// arch (`make bpf`) to ship elsewhere; where the object does not load,
// UDP accounting simply reports itself unavailable.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -output-stem udpbpf -cc clang -target native udp bpf/udp.c -- -I/usr/include -Ibpf -O2 -Wall

// UDPStats gives UDP rows the per-socket byte counters the kernel does not
// keep, by way of a small eBPF program. It is strictly optional: if the
// kernel, the capabilities, or the attach points are not there, Available
// stays false, every UDP row keeps reading zero, and the group header
// tooltip says that traffic is unattributed rather than lying about it.
//
// Same shape as TCPStats on purpose: Apply mutates a conn slice in place
// with deltas since the previous call, so the two sources are
// interchangeable from the broadcast loop's point of view.
type UDPStats struct {
	mu     sync.Mutex
	objs   udpObjects
	links  []link.Link
	avail  bool
	why    string // why it is unavailable, for the UI and the log
	prev   map[string]udpCounters
	cum    map[string]*udpTraffic
	primed bool
	last   time.Time
}

type udpCounters struct {
	tx, rx uint64
}

// udpTraffic is the running total for one socket. The Conn rows are
// rebuilt from /proc every tick, so anything cumulative has to live here
// — same reason tcpstats.go keeps connTraffic.
type udpTraffic struct {
	upKB, downKB     float64
	upRate, downRate float64
	lastSeen         time.Time
}

// NewUDPStats loads and attaches the program, or explains why it could
// not. It never returns an error: absence of UDP accounting degrades the
// display, it does not stop the monitor.
func NewUDPStats() *UDPStats {
	u := &UDPStats{
		prev: make(map[string]udpCounters),
		cum:  make(map[string]*udpTraffic),
	}

	// Kernels before 5.11 charged BPF maps against RLIMIT_MEMLOCK; since
	// then they use memory cgroup accounting and this call is unnecessary.
	// Failing it is therefore not a reason to give up — try the load and
	// let the real error be the one reported.
	rlimit.RemoveMemlock()
	if err := loadUdpObjects(&u.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		switch {
		case errors.Is(err, os.ErrPermission):
			// Overwhelmingly the common case, and the one with a fix.
			u.why = "not permitted to load eBPF — the binary needs the " +
				"cap_bpf and cap_perfmon capabilities (`make install` grants them)"
		case errors.As(err, &ve):
			// The verifier log runs to hundreds of lines; the first is
			// the one that says what it objected to.
			u.why = "the kernel rejected the program: " + firstLine(ve.Error())
		default:
			u.why = "cannot load the program: " + firstLine(err.Error())
		}
		return u
	}

	// Each probe is attached independently: a kernel that renamed one of
	// them should still give us the other direction rather than nothing.
	type probe struct {
		sym string
		prg *ebpf.Program
	}
	probes := []probe{
		{"udp_sendmsg", u.objs.UdpSend},
		{"udpv6_sendmsg", u.objs.Udpv6Send},
		{"skb_consume_udp", u.objs.UdpConsume},
	}
	var failed []string
	for _, p := range probes {
		l, err := link.Kprobe(p.sym, p.prg, nil)
		if err != nil {
			failed = append(failed, p.sym)
			continue
		}
		u.links = append(u.links, l)
	}
	if len(u.links) == 0 {
		u.objs.Close()
		u.why = "cannot attach to the kernel's UDP path (" +
			strings.Join(failed, ", ") + ") — needs CAP_BPF and CAP_PERFMON"
		return u
	}
	if len(failed) > 0 {
		log.Printf("udp accounting: partial — could not attach %s",
			strings.Join(failed, ", "))
	}
	u.avail = true
	return u
}

// Available reports whether UDP rows carry real numbers.
func (u *UDPStats) Available() bool { return u != nil && u.avail }

// Why explains the unavailability, "" when available.
func (u *UDPStats) Why() string {
	if u == nil {
		return "not initialised"
	}
	if u.avail {
		return ""
	}
	return u.why
}

func (u *UDPStats) Close() {
	if u == nil {
		return
	}
	for _, l := range u.links {
		l.Close()
	}
	if u.avail {
		u.objs.Close()
	}
}

// Apply fills UpKB/DownKB/UpRate/DownRate on the UDP rows of conns.
// No-op when unavailable, so callers need no branch.
func (u *UDPStats) Apply(conns []Conn) {
	if !u.Available() {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	now := time.Now()
	dt := now.Sub(u.last).Seconds()
	u.last = now

	cur := make(map[string]udpCounters, len(u.prev))
	var (
		key udpUdpKey
		val udpUdpVal
	)
	it := u.objs.UdpBytes.Iterate()
	for it.Next(&key, &val) {
		cur[key.id()] = udpCounters{tx: val.Tx, rx: val.Rx}
	}
	if err := it.Err(); err != nil {
		return // transient; keep the previous baseline and try next tick
	}

	// The first pass after startup baselines every socket that already
	// existed, so long-lived sockets do not dump their lifetime total
	// into one tick as a huge fake spike. Sockets that appear later are
	// counted in full, same rule tcpstats.go uses.
	if !u.primed {
		u.prev = cur
		u.primed = true
		return
	}

	// Fold this tick's deltas into the running totals, for every socket
	// the map knows about — not just the ones with a row right now, so a
	// socket that blinks out of /proc for a tick doesn't lose bytes.
	for k, cnt := range cur {
		was, existed := u.prev[k]
		dtx, drx := cnt.tx-was.tx, cnt.rx-was.rx
		if !existed {
			// First sighting after priming: the whole counter accrued on
			// our watch. Same rule tcpstats.go uses for new sockets.
			dtx, drx = cnt.tx, cnt.rx
		} else if cnt.tx < was.tx || cnt.rx < was.rx {
			dtx, drx = 0, 0 // went backwards: LRU evicted and the key was reused
		}
		e := u.cum[k]
		if e == nil {
			e = &udpTraffic{}
			u.cum[k] = e
		}
		e.upKB += float64(dtx) / 1024
		e.downKB += float64(drx) / 1024
		if dt > 0 {
			e.upRate = float64(dtx) / 1024 / dt
			e.downRate = float64(drx) / 1024 / dt
		} else {
			e.upRate, e.downRate = 0, 0
		}
		e.lastSeen = now
	}
	// A socket the map has dropped is gone: stop reporting a stale rate
	// for it, and eventually forget it.
	for k, e := range u.cum {
		if _, live := cur[k]; !live {
			e.upRate, e.downRate = 0, 0
			if now.Sub(e.lastSeen) > 60*time.Second {
				delete(u.cum, k)
			}
		}
	}

	for i := range conns {
		c := &conns[i]
		if !strings.HasPrefix(c.Proto, "udp") {
			continue
		}
		k, ok := connUDPKey(c)
		if !ok {
			continue
		}
		if e := u.cum[k]; e != nil {
			c.UpKB, c.DownKB = e.upKB, e.downKB
			c.UpRate, c.DownRate = e.upRate, e.downRate
		}
	}
	u.prev = cur
}

// id renders a map key the way connUDPKey does, so the two meet.
func (k *udpUdpKey) id() string {
	var l, r netip.Addr
	if k.Family == 6 {
		var lb, rb [16]byte
		putWords(lb[:], k.Saddr[:])
		putWords(rb[:], k.Daddr[:])
		l, r = netip.AddrFrom16(lb), netip.AddrFrom16(rb)
		if l.Is4In6() {
			l = l.Unmap()
		}
		if r.Is4In6() {
			r = r.Unmap()
		}
	} else {
		l = netip.AddrFrom4(word4(k.Saddr[0]))
		r = netip.AddrFrom4(word4(k.Daddr[0]))
	}
	return fmt.Sprintf("%s:%d|%s:%d", l, k.Sport, r, k.Dport)
}

func connUDPKey(c *Conn) (string, bool) {
	if c.LAddr == "" || c.LAddr == "invalid IP" {
		return "", false
	}
	return fmt.Sprintf("%s:%d|%s:%d", c.LAddr, c.LPort, c.RAddr, c.RPort), true
}

// The kernel stores v4 addresses and v6 words in network byte order, and
// netip wants plain bytes, so the words go out big-endian as they sit.
func word4(w uint32) [4]byte {
	return [4]byte{byte(w), byte(w >> 8), byte(w >> 16), byte(w >> 24)}
}

func putWords(dst []byte, ws []uint32) {
	for i, w := range ws {
		b := word4(w)
		copy(dst[i*4:], b[:])
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
