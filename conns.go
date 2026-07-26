package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
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
	// NoPID says why a row has no process attached, so the UI can tell the
	// harmless case apart from the broken one:
	//   "noproc" the kernel keeps no process for this socket (TIME_WAIT and
	//            friends are inet_timewait_sock: no fd, no inode, no owner)
	//   "denied" the owning process exists but we cannot read its fds
	//   "kernel" a kernel-internal socket: it has an inode, but no process
	//            holds it and none ever will (see kernelUnowned)
	//   "gone"   it exited between the /proc walk and this scan
	NoPID string `json:"noPid,omitempty"`
	// Inherit marks a row whose Comm/App/PID did not come from the kernel this
	// tick but from LastOwners — the last process we saw holding this exact
	// 4-tuple. The attribution is true of the socket's past, not its present,
	// and the UI dims it to say so.
	Inherit bool `json:"inherit,omitempty"`
	// WasPID is the former owner's PID, set only when that process is no
	// longer alive (or its number has been recycled). It is deliberately not
	// PID: it exists to answer "what was this", not to be killed.
	WasPID int `json:"wasPid,omitempty"`
}

// capsNeeded mirrors CAPS in the Makefile. Kept here so the runtime hint
// prints a command that actually works, rather than sending the user off to
// find the right incantation.
const capsNeeded = "cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace,cap_bpf,cap_perfmon"

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
	// blocked counts processes whose /proc/<pid>/fd we were refused in the
	// last walk. Non-zero means attribution is degraded, not that a
	// particular row is: it is the difference between "this socket has no
	// owner" and "we are not allowed to see the owner".
	blocked int
	warned  bool
	// unowned remembers, per socket inode, when we first saw a socket that
	// has an inode but that no /proc/<pid>/fd points at. See kernelUnowned.
	unowned map[uint64]time.Time
	// everOwned remembers, per socket inode, that some process once held an
	// fd on it. Once its owner exits, a socket that belonged to a program is
	// byte-for-byte indistinguishable from one the kernel opened for itself,
	// and the age test alone then calls both kernel-owned. That is wrong in
	// the one direction that costs a name: the sockets it mislabels are
	// exactly the long-lived corpses whose owner you most want reported.
	// Both maps are pruned to the live inode set on every scan.
	everOwned map[uint64]bool
}

// How long a socket must keep an inode that no process holds before we stop
// calling it a race and call it kernel-owned. A process exiting between the
// /proc walk and the scan leaves such a socket for a tick or two; the socket
// dies with it. A kernel-internal socket — NFS's lockd publishes four of
// them, nlockmgr over tcp and udp, v4 and v6 — keeps its inode for the
// lifetime of the mount with no userspace owner at any point, so without
// this it is reported as "just exited" on every tick forever. That is not a
// cosmetic wrong label: those permanent rows drowned the real exit races in
// the counts (720 of 782 in one 180-snapshot sample).
const kernelUnowned = 10 * time.Second

// Blocked reports how many processes were unreadable in the last /proc
// walk. Zero means every socket that has an owner could be attributed.
func (s *Scanner) Blocked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blocked
}

func NewScanner() *Scanner {
	return &Scanner{
		inodePID:  make(map[uint64]int),
		unowned:   make(map[uint64]time.Time),
		everOwned: make(map[uint64]bool),
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
	// A socket that has been unowned for kernelUnowned is not "unknown": no
	// walk is going to find it an owner, whether because it never had one or
	// because the one it had is long gone. Treating it as a reason to walk
	// means a full /proc sweep on every single tick for as long as it exists.
	missing := false
	for _, r := range raws {
		if r.inode != 0 {
			if _, ok := s.inodePID[r.inode]; !ok && !s.staleUnowned(r.inode, time.Now()) {
				missing = true
				break
			}
		}
	}
	if missing || time.Since(s.lastWalk) > 30*time.Second {
		s.walkProc()
	}

	// Age every socket that has an inode no process holds. Done after the
	// walk, so the map it is compared against is the current one, and in one
	// pass over the whole scan, so inodes that have gone away are dropped
	// rather than accumulating for the life of the process.
	now := time.Now()
	live := make(map[uint64]bool, len(raws))
	for _, r := range raws {
		if r.inode == 0 {
			continue
		}
		live[r.inode] = true
		if _, owned := s.inodePID[r.inode]; owned {
			// Attributable right now, so it is not kernel-internal and never
			// will be. Clear any age it accrued during a walk race.
			s.everOwned[r.inode] = true
			delete(s.unowned, r.inode)
			continue
		}
		if _, ok := s.unowned[r.inode]; !ok {
			s.unowned[r.inode] = now
		}
	}
	for ino := range s.unowned {
		if !live[ino] {
			delete(s.unowned, ino)
		}
	}
	for ino := range s.everOwned {
		if !live[ino] {
			delete(s.everOwned, ino)
		}
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
		} else if r.inode == 0 {
			// No inode at all: the kernel is not holding a socket with an
			// owner here. Nothing is wrong and nothing can be attributed.
			c.NoPID = "noproc"
		} else {
			c.NoPID = s.unownedReason(r.inode, now)
		}
		c.CC, c.Flag = geoLookup(ra)
		c.ID = fmt.Sprintf("%s|%s:%d|%s:%d", c.Proto, c.LAddr, c.LPort, c.RAddr, c.RPort)
		conns = append(conns, c)
	}
	return conns
}

// unownedReason explains a socket that has an inode which no fd points at.
// Caller holds the lock.
func (s *Scanner) unownedReason(inode uint64, now time.Time) string {
	if s.blocked > 0 {
		// There is an owner; we were refused somewhere in this walk, so the
		// overwhelmingly likely reason is that it was this one. Said before
		// the age test, because a socket we are not allowed to see the owner
		// of looks exactly like one that has none.
		return "denied"
	}
	if s.kernelOwned(inode, now) {
		return "kernel"
	}
	return "gone"
}

// staleUnowned reports whether this inode has gone unowned for long enough
// that another /proc walk will not turn up an owner. Caller holds the lock.
func (s *Scanner) staleUnowned(inode uint64, now time.Time) bool {
	first, ok := s.unowned[inode]
	return ok && now.Sub(first) >= kernelUnowned
}

// kernelOwned reports whether this inode belongs to the kernel itself: nothing
// holds it, and nothing ever did. Age alone is not enough to conclude that.
// A socket whose owner exited keeps its inode for as long as the peer leaves
// the connection up, which on a real link is minutes, not the seconds the age
// test allows — so without the everOwned check every long-running download
// whose process dies is filed as kernel-internal, and "kernel" is the one
// reason that is never resolved from LastOwners, because a socket that never
// had an owner cannot have a remembered one. The name is thrown away for
// precisely the rows that have a name to show. Caller holds the lock.
func (s *Scanner) kernelOwned(inode uint64, now time.Time) bool {
	if s.everOwned[inode] {
		return false
	}
	return s.staleUnowned(inode, now)
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
	blocked := 0
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		livePids[pid] = true
		fds, err := os.ReadDir("/proc/" + p.Name() + "/fd")
		if err != nil {
			// A process exiting mid-walk is ordinary churn. Permission
			// denied is not: it means this build cannot see other users'
			// sockets, and every one of them will show up unattributed with
			// no hint as to why. Count it so we can say so out loud.
			if errors.Is(err, os.ErrPermission) {
				blocked++
			}
			continue
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
	s.blocked = blocked
	// Say it once, at the log, with the fix in it. Silent degradation is
	// what made this hard to diagnose: the rows just render as "—" and
	// "root" and look like a mystery root process rather than a missing
	// capability.
	if blocked > 0 && !s.warned {
		s.warned = true
		exe, err := os.Executable()
		if err != nil {
			exe = "/path/to/porthawk"
		}
		log.Printf("socket attribution degraded — %d process(es) refused us /proc/<pid>/fd", blocked)
		log.Printf("attribution: their connections show as \"—\" with no PID. To fix:")
		log.Printf("attribution:   sudo setcap \"%s+eip\" %s", capsNeeded, exe)
		log.Printf("attribution: then restart. File caps live on the inode, so every rebuild drops them.")
	}
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
