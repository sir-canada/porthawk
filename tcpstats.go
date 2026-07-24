package main

import (
	"bufio"
	"bytes"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-connection TCP traffic from kernel tcp_info (ss -ti):
// bytes_sent / bytes_received are cumulative per socket. Rates come from
// deltas between ticks; totals count only traffic observed while
// monitoring (pre-existing sockets are baselined on the first tick).
// UDP has no per-socket byte counters — those rows stay empty and are
// covered by the per-process nethogs numbers.

type connTraffic struct {
	upKB, downKB     float64
	upRate, downRate float64 // KB/s
	rawSent, rawRecv uint64
	lastSeen         time.Time
}

type TCPStats struct {
	mu     sync.Mutex
	m      map[string]*connTraffic // "la|lp|ra|rp"
	last   time.Time
	primed bool // first tick done: later-appearing sockets count in full
}

func NewTCPStats() *TCPStats { return &TCPStats{m: map[string]*connTraffic{}} }

// Apply refreshes counters and fills the traffic fields of conns in place.
func (t *TCPStats) Apply(conns []Conn) {
	out, err := exec.Command("ss", "-ntiHO").Output()
	if err != nil {
		return
	}
	now := time.Now()
	dt := now.Sub(t.last).Seconds()
	if dt <= 0 || dt > 10 {
		dt = 1
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != "ESTAB" {
			continue
		}
		la, lp, ok1 := splitHostPort(f[3])
		ra, rp, ok2 := splitHostPort(f[4])
		if !ok1 || !ok2 {
			continue
		}
		var sent, recv uint64
		var haveSent bool
		for _, tok := range f[5:] {
			switch {
			case strings.HasPrefix(tok, "bytes_sent:"):
				sent, _ = strconv.ParseUint(tok[11:], 10, 64)
				haveSent = true
			case strings.HasPrefix(tok, "bytes_acked:"):
				if !haveSent { // older kernels lack bytes_sent
					sent, _ = strconv.ParseUint(tok[12:], 10, 64)
				}
			case strings.HasPrefix(tok, "bytes_received:"):
				recv, _ = strconv.ParseUint(tok[15:], 10, 64)
			}
		}
		key := la + "|" + lp + "|" + ra + "|" + rp
		e := t.m[key]
		if e == nil {
			e = &connTraffic{}
			t.m[key] = e
			if t.primed {
				// Socket born after monitoring started: whole counter
				// accrued on our watch.
				e.upKB = float64(sent) / 1024
				e.downKB = float64(recv) / 1024
				e.upRate = e.upKB / dt
				e.downRate = e.downKB / dt
			}
		} else {
			dS, dR := sent-e.rawSent, recv-e.rawRecv
			if sent < e.rawSent { // tuple reused by a new socket
				dS = sent
			}
			if recv < e.rawRecv {
				dR = recv
			}
			e.upKB += float64(dS) / 1024
			e.downKB += float64(dR) / 1024
			e.upRate = float64(dS) / 1024 / dt
			e.downRate = float64(dR) / 1024 / dt
		}
		e.rawSent, e.rawRecv = sent, recv
		e.lastSeen = now
	}
	for k, e := range t.m {
		if now.Sub(e.lastSeen) > 60*time.Second {
			delete(t.m, k)
		}
	}
	t.last = now
	t.primed = true

	for i := range conns {
		c := &conns[i]
		if !strings.HasPrefix(c.Proto, "tcp") {
			continue
		}
		key := c.LAddr + "|" + strconv.Itoa(int(c.LPort)) + "|" +
			c.RAddr + "|" + strconv.Itoa(int(c.RPort))
		if e, ok := t.m[key]; ok {
			c.UpKB, c.DownKB = e.upKB, e.downKB
			c.UpRate, c.DownRate = e.upRate, e.downRate
		}
	}
}

// splitHostPort parses ss address forms "1.2.3.4:80" and "[v6]:80",
// normalizing the host to match Scanner output (unmapped netip.String).
func splitHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	host, port = strings.Trim(s[:i], "[]"), s[i+1:]
	if strings.HasSuffix(host, "%") { // stray iface suffix guard
		return "", "", false
	}
	if j := strings.IndexByte(host, '%'); j >= 0 { // fe80::1%wlan0
		host = host[:j]
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return "", "", false
	}
	return a.Unmap().String(), port, true
}
