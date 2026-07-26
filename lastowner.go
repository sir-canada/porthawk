package main

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// How long a socket's last known owner is remembered after the kernel stops
// telling us who it is. Sized for TIME_WAIT, which is 2*MSL — 60s on Linux —
// so a socket that spends its whole TIME_WAIT unattributed still carries the
// name of the process that opened it for the entire time it is on screen.
const lastOwnerTTL = 120 * time.Second

// ownerMemo is one remembered attribution: who owned this socket the last
// time the kernel let us see an owner.
//
// start is the process start time from /proc/<pid>/stat, and it is the whole
// reason a PID can be shown at all. PIDs are recycled; a number cached three
// minutes ago may now name an unrelated process, and offering that to kill(1)
// would be worse than offering nothing. Start time is assigned by the kernel
// at exec and never changes, so (pid, start) identifies a process run
// uniquely: if both still match, it is the same process, not a namesake.
type ownerMemo struct {
	pid   int
	comm  string
	app   string
	start uint64
	seen  time.Time
}

// LastOwners remembers, per socket 4-tuple, the process that last owned it.
//
// The 4-tuple is the right key precisely because it survives the transition
// this exists to cover: a socket entering TIME_WAIT keeps the same addresses
// and ports it had while ESTABLISHED, it just loses its inode and therefore
// its owner. So the lookup is an identity, not a guess — this is the same
// socket, and we saw who owned it one tick ago.
type LastOwners struct {
	mu sync.Mutex
	m  map[string]ownerMemo
}

func NewLastOwners() *LastOwners {
	return &LastOwners{m: map[string]ownerMemo{}}
}

// procStart reads field 22 (starttime) of /proc/<pid>/stat.
//
// The file cannot be split on whitespace from the left: field 2 is the comm,
// it is wrapped in parentheses, and it may contain both spaces and closing
// parens ("(Web Content)", "(a) b)"). Everything after the *last* ')' is
// fixed-width and safe to split, and there the first field is stat field 3,
// so field 22 sits at index 19.
// Indirected through a var so tests can describe a process table instead of
// depending on whatever happens to be running on the machine — low PIDs are
// live kernel threads on a real host, which makes any fixed test PID a
// coin flip.
var procStart = readProcStart

func readProcStart(pid int) (uint64, bool) {
	return readProcStatFile("/proc/" + strconv.Itoa(pid) + "/stat")
}

func readProcStatFile(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) <= 19 {
		return 0, false
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// alive reports whether pid still names the same process run that was
// recorded. A missing /proc entry means it exited; a different start time
// means the number was recycled. Both answer "no".
func (m ownerMemo) alive() bool {
	if m.pid <= 0 || m.start == 0 {
		return false
	}
	now, ok := procStart(m.pid)
	return ok && now == m.start
}

// Record notes the current owner of every attributed connection, and expires
// entries past the TTL. starts memoizes the /proc read per pid for this call:
// a process with forty open sockets costs one stat read, not forty.
func (l *LastOwners) Record(live []Conn, now time.Time) {
	starts := map[int]uint64{}
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, c := range live {
		if c.PID <= 0 || c.Comm == "" {
			continue
		}
		st, seen := starts[c.PID]
		if !seen {
			st, _ = procStart(c.PID)
			starts[c.PID] = st
		}
		l.m[c.ID] = ownerMemo{pid: c.PID, comm: c.Comm, app: c.App, start: st, seen: now}
	}
	for id, m := range l.m {
		if now.Sub(m.seen) > lastOwnerTTL {
			delete(l.m, id)
		}
	}
}

// Resolve fills in the owner of a connection the kernel will not attribute,
// from memory. Returns true if anything was filled in.
//
// The PID is only restored when the owning process is still the one we
// recorded (see ownerMemo.start). When it is gone, the name is still worth
// showing — "this was firefox" is the answer to the question the row raises —
// but the number is not, so it is parked in WasPID for the tooltip and the
// PID column stays empty rather than naming a process that no longer exists.
func (l *LastOwners) Resolve(c *Conn) bool {
	l.mu.Lock()
	m, ok := l.m[c.ID]
	l.mu.Unlock()
	if !ok || m.comm == "" {
		return false
	}
	c.Comm, c.App, c.Inherit = m.comm, m.app, true
	if m.alive() {
		c.PID = m.pid
	} else {
		c.WasPID = m.pid
	}
	return true
}

// Verify re-checks a connection that carries a live PID and demotes it if the
// process has since exited or the number has been recycled.
//
// Ghosts need this on every tick, not just at promotion: a row lingers for the
// whole ghost window, and the process that owned it commonly dies partway
// through — that is usually *why* the socket died. Without the recheck the
// corpse keeps advertising a PID that drifts from stale to actively wrong the
// moment the kernel hands that number to something else.
func (l *LastOwners) Verify(c *Conn) {
	if c.PID <= 0 {
		return
	}
	l.mu.Lock()
	m, ok := l.m[c.ID]
	l.mu.Unlock()
	if !ok || m.pid != c.PID {
		return
	}
	if !m.alive() {
		c.WasPID, c.PID, c.Inherit = c.PID, -1, true
	}
}
