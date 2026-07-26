package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Conn is one socket row shipped to the frontend.
type Conn struct {
	ID    string `json:"id"`
	Proto string `json:"proto"`
	State string `json:"state"`
	LAddr string `json:"la"`
	LPort uint16 `json:"lp"`
	RAddr string `json:"ra"`
	RPort uint16 `json:"rp"`
	PID   int    `json:"pid"`
	Comm  string `json:"comm"`
	App   string `json:"app"` // recognizable app/instance name, "" = use comm
	UID   uint32 `json:"uid"`
	User  string `json:"user"`
	CC    string `json:"cc"`   // ISO country code, "" = n/a
	Flag  string `json:"flag"` // emoji
	Host  string `json:"host"` // reverse DNS of the peer, "" = unresolved
	// Local-side naming, same sources as the remote side: the local
	// address is an address like any other, and on a multi-homed or
	// publicly-addressed host it is worth naming too.
	LHost  string `json:"lhost,omitempty"`
	LOwner string `json:"lowner,omitempty"`
	LAlias string `json:"lalias,omitempty"`
	// Iface/LIface name the local network adapter the address is assigned
	// to, e.g. wlan0. Set only for addresses the kernel says are ours, and
	// preferred over reverse DNS and ownership for those: the hostname is
	// the same for every interface, the adapter name is not.
	Iface  string `json:"if,omitempty"`
	LIface string `json:"lif,omitempty"`
	// Owner is who the IP range is registered to (RDAP), used when reverse
	// DNS yields nothing. Alias is the user's own name for this address.
	// Hide marks a row as matching a user hide rule — the row is still
	// sent, so the UI can unhide instantly and count what's suppressed.
	Owner string `json:"owner,omitempty"`
	Pfx   string `json:"pfx,omitempty"` // owning range, e.g. 160.79.104.0/21
	Alias string `json:"alias,omitempty"`
	Hide  bool   `json:"hide,omitempty"`
	// per-connection traffic (TCP only, from tcp_info; UDP has none)
	UpKB     float64 `json:"up,omitempty"`
	DownKB   float64 `json:"down,omitempty"`
	UpRate   float64 `json:"upRate,omitempty"`
	DownRate float64 `json:"downRate,omitempty"`
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

// Scanner maps kernel socket tables to attributed connections.
type Scanner struct {
	mu        sync.Mutex
	inodePID  map[uint64]int    // socket inode -> pid
	commCache map[int]string    // pid -> comm
	appCache  map[int]string    // pid -> app label
	userCache map[uint32]string // uid -> username
	lastWalk  time.Time
}

func NewScanner() *Scanner {
	return &Scanner{
		inodePID:  make(map[uint64]int),
		commCache: make(map[int]string),
		appCache:  make(map[int]string),
		userCache: make(map[uint32]string),
	}
}

// Scan returns the current connection set.
func (s *Scanner) Scan() []Conn {
	type raw struct {
		proto      string
		local, rem string
		state      string
		uid        uint32
		inode      uint64
	}
	var raws []raw
	for _, f := range [...]struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	} {
		fh, err := os.Open(f.path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 10 {
				continue
			}
			uid64, _ := strconv.ParseUint(fl[7], 10, 32)
			inode, _ := strconv.ParseUint(fl[9], 10, 64)
			raws = append(raws, raw{f.proto, fl[1], fl[2], fl[3], uint32(uid64), inode})
		}
		fh.Close()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Walk /proc if any inode is unknown, or periodically to evict stale.
	missing := false
	for _, r := range raws {
		if r.inode != 0 {
			if _, ok := s.inodePID[r.inode]; !ok {
				missing = true
				break
			}
		}
	}
	if missing || time.Since(s.lastWalk) > 30*time.Second {
		s.walkProc()
	}

	conns := make([]Conn, 0, len(raws))
	for _, r := range raws {
		la, lp := parseHexAddr(r.local)
		ra, rp := parseHexAddr(r.rem)
		c := Conn{
			Proto: r.proto,
			LAddr: la.String(),
			LPort: lp,
			RAddr: ra.String(),
			RPort: rp,
			UID:   r.uid,
			User:  s.username(r.uid),
			PID:   -1,
		}
		if strings.HasPrefix(r.proto, "tcp") {
			c.State = tcpStates[r.state]
		} else if ra.IsUnspecified() && rp == 0 {
			c.State = "UNCONN"
		} else {
			c.State = "ESTABLISHED"
		}
		if pid, ok := s.inodePID[r.inode]; ok && r.inode != 0 {
			c.PID = pid
			c.Comm = s.comm(pid)
			c.App = s.appLocked(pid, c.Comm)
		}
		c.CC, c.Flag = geoLookup(ra)
		c.ID = fmt.Sprintf("%s|%s:%d|%s:%d", c.Proto, c.LAddr, c.LPort, c.RAddr, c.RPort)
		conns = append(conns, c)
	}
	return conns
}

// walkProc rebuilds the socket-inode -> pid map. Needs
// cap_dac_read_search + cap_sys_ptrace to see other users' fds.
func (s *Scanner) walkProc() {
	fresh := make(map[uint64]int, len(s.inodePID))
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	livePids := make(map[int]bool, len(procs))
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		livePids[pid] = true
		fds, err := os.ReadDir("/proc/" + p.Name() + "/fd")
		if err != nil {
			continue // gone or unreadable
		}
		for _, fd := range fds {
			link, err := os.Readlink("/proc/" + p.Name() + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(link[8:len(link)-1], 10, 64)
			if err == nil {
				fresh[inode] = pid
			}
		}
	}
	s.inodePID = fresh
	for pid := range s.commCache {
		if !livePids[pid] {
			delete(s.commCache, pid)
			delete(s.appCache, pid)
		}
	}
	s.lastWalk = time.Now()
}

// appLocked returns the cached app label for pid (caller holds s.mu).
func (s *Scanner) appLocked(pid int, comm string) string {
	if a, ok := s.appCache[pid]; ok {
		return a
	}
	a := appIdentity(pid, comm)
	s.appCache[pid] = a
	return a
}

// App returns the app label for pid, resolving comm as needed. Safe for
// callers outside Scan (takes the lock itself).
func (s *Scanner) App(pid int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.appCache[pid]; ok {
		return a
	}
	return s.appLocked(pid, s.comm(pid))
}

func (s *Scanner) comm(pid int) string {
	if c, ok := s.commCache[pid]; ok {
		return c
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return "?"
	}
	c := strings.TrimSpace(string(b))
	s.commCache[pid] = c
	return c
}

func (s *Scanner) username(uid uint32) string {
	if u, ok := s.userCache[uid]; ok {
		return u
	}
	name := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	s.userCache[uid] = name
	return name
}

// parseHexAddr decodes "0100007F:1F90" (v4) or 32-hex-char v6 form.
// Kernel prints each 32-bit word in host (little-endian) byte order.
func parseHexAddr(s string) (netip.Addr, uint16) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return netip.Addr{}, 0
	}
	hexIP, hexPort := s[:i], s[i+1:]
	port64, _ := strconv.ParseUint(hexPort, 16, 16)
	port := uint16(port64)

	switch len(hexIP) {
	case 8:
		v, err := strconv.ParseUint(hexIP, 16, 32)
		if err != nil {
			return netip.Addr{}, port
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		return netip.AddrFrom4(b), port
	case 32:
		var b [16]byte
		for w := 0; w < 4; w++ {
			v, err := strconv.ParseUint(hexIP[w*8:w*8+8], 16, 32)
			if err != nil {
				return netip.Addr{}, port
			}
			binary.LittleEndian.PutUint32(b[w*4:], uint32(v))
		}
		a := netip.AddrFrom16(b)
		if a.Is4In6() {
			a = a.Unmap()
		}
		return a, port
	}
	return netip.Addr{}, port
}
