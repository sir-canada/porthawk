package main

import (
	"testing"
	"time"
)

// find reports whether a connection id is present with the given state.
func find(conns []Conn, id, state string) bool {
	for _, c := range conns {
		if c.ID == id && c.State == state {
			return true
		}
	}
	return false
}

func TestGhostLingersThenExpires(t *testing.T) {
	g := NewGhosts(60 * time.Millisecond)
	live := []Conn{{ID: "a", State: "ESTABLISHED"}}

	g.Track(live)       // first tick: seen alive
	out := g.Track(nil) // second tick: gone
	if !find(out, "a", "DISCONNECTED") {
		t.Fatal("vanished ESTABLISHED conn should be held as DISCONNECTED")
	}
	if out := g.Track(nil); !find(out, "a", "DISCONNECTED") {
		t.Fatal("ghost should still be held inside its window")
	}
	time.Sleep(80 * time.Millisecond)
	if out := g.Track(nil); len(out) != 0 {
		t.Fatalf("ghost should be gone after its window, got %v", out)
	}
}

// A returning connection cancels its own ghost rather than showing twice.
func TestGhostCancelledByReturn(t *testing.T) {
	g := NewGhosts(time.Minute)
	live := []Conn{{ID: "a", State: "ESTABLISHED"}}
	g.Track(live)
	g.Track(nil)
	out := g.Track(live)
	if len(out) != 1 || out[0].State != "ESTABLISHED" {
		t.Fatalf("returning conn should replace its ghost, got %v", out)
	}
}

// Zero is a real setting, not "unset": dead sockets must disappear at once.
func TestGhostTTLZeroDisables(t *testing.T) {
	g := NewGhosts(0)
	live := []Conn{{ID: "a", State: "ESTABLISHED"}}
	g.Track(live)
	if out := g.Track(nil); len(out) != 0 {
		t.Fatalf("ttl 0 should hold no ghosts, got %v", out)
	}
}

// Shortening the window must expire ghosts already being held, not just
// apply to future ones — Track compares against the live value each tick.
func TestGhostTTLChangeAppliesToHeldGhosts(t *testing.T) {
	g := NewGhosts(time.Minute)
	live := []Conn{{ID: "a", State: "ESTABLISHED"}}
	g.Track(live)
	if out := g.Track(nil); !find(out, "a", "DISCONNECTED") {
		t.Fatal("expected a held ghost before the change")
	}
	g.SetTTL(0)
	if out := g.Track(nil); len(out) != 0 {
		t.Fatalf("held ghosts should drop when the window is turned off, got %v", out)
	}
}

// Turning ghosting back on must not resurrect everything that died while
// it was off: the diff restarts from the tick it was re-enabled.
func TestGhostTTLReenableDoesNotResurrect(t *testing.T) {
	g := NewGhosts(0)
	g.Track([]Conn{{ID: "a", State: "ESTABLISHED"}})
	g.Track(nil) // "a" dies here, while ghosting is off
	g.SetTTL(time.Minute)
	if out := g.Track(nil); len(out) != 0 {
		t.Fatalf("conn that died while ghosting was off should stay gone, got %v", out)
	}
	// A conn that dies *after* re-enabling is ghosted as normal.
	g.Track([]Conn{{ID: "b", State: "ESTABLISHED"}})
	if out := g.Track(nil); !find(out, "b", "DISCONNECTED") {
		t.Fatal("ghosting should work again once re-enabled")
	}
}

func TestClampGhostTTL(t *testing.T) {
	for _, tc := range []struct{ in, want time.Duration }{
		{-time.Second, 0},
		{0, 0},
		{45 * time.Second, 45 * time.Second},
		{maxGhostTTL, maxGhostTTL},
		{time.Hour, maxGhostTTL},
	} {
		if got := clampGhostTTL(tc.in); got != tc.want {
			t.Errorf("clampGhostTTL(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// fakeProcs installs a stubbed process table for the duration of a test:
// pid -> start time, absent means the pid does not exist.
func fakeProcs(t *testing.T, procs map[int]uint64) {
	t.Helper()
	orig := procStart
	procStart = func(pid int) (uint64, bool) {
		st, ok := procs[pid]
		return st, ok
	}
	t.Cleanup(func() { procStart = orig })
}

// A process exits, its socket outlives it by a tick, and that unattributed
// tick is what gets promoted to a ghost — so without carrying the name
// across, every corpse is anonymous.
func TestGhostKeepsNameOfExitedProcess(t *testing.T) {
	procs := map[int]uint64{42: 1000}
	fakeProcs(t, procs)

	g := NewGhosts(time.Minute)
	g.Track([]Conn{{ID: "a", State: "ESTABLISHED", PID: 42, Comm: "brave", App: "Brave"}})
	delete(procs, 42) // owner exits

	// Same socket, owner exited: kernel reports it with no pid.
	out := g.Track([]Conn{{ID: "a", State: "ESTABLISHED", PID: -1, NoPID: "gone"}})
	if len(out) != 1 || out[0].Comm != "brave" || out[0].App != "Brave" {
		t.Fatalf("name should survive the owner exiting, got %+v", out)
	}
	if out[0].PID != -1 {
		t.Fatalf("dead owner's PID must not reach the PID column, got %d", out[0].PID)
	}
	if out[0].WasPID != 42 || !out[0].Inherit {
		t.Fatalf("former PID should be recorded as WasPID and flagged inherited, got %+v", out[0])
	}

	// And it is still there once the socket goes and the row is a ghost.
	out = g.Track(nil)
	if len(out) != 1 || out[0].State != "DISCONNECTED" || out[0].Comm != "brave" {
		t.Fatalf("ghost should keep the name, got %+v", out)
	}
}

// TIME_WAIT is the volume case: the kernel keeps no process for these, but the
// 4-tuple is the same one that was ESTABLISHED a second earlier, so the owner
// is known by identity rather than guessed.
func TestTimeWaitInheritsOwner(t *testing.T) {
	procs := map[int]uint64{42: 1000}
	fakeProcs(t, procs)

	g := NewGhosts(time.Minute)
	g.Track([]Conn{{ID: "a", State: "ESTABLISHED", PID: 42, Comm: "brave", App: "Brave"}})
	out := g.Track([]Conn{{ID: "a", State: "TIME_WAIT", PID: -1, NoPID: "noproc"}})
	if len(out) != 1 || out[0].Comm != "brave" || !out[0].Inherit {
		t.Fatalf("TIME_WAIT should inherit its opener, got %+v", out)
	}
	// Owner still running, so the PID is real and usable.
	if out[0].PID != 42 {
		t.Fatalf("live owner's PID should be restored, got %d", out[0].PID)
	}
}

// A PID recycled onto a different process must not be offered as this
// socket's owner: same number, different start time, different process.
func TestInheritedPIDRejectsRecycledNumber(t *testing.T) {
	procs := map[int]uint64{42: 1000}
	fakeProcs(t, procs)

	g := NewGhosts(time.Minute)
	g.Track([]Conn{{ID: "a", State: "ESTABLISHED", PID: 42, Comm: "brave"}})
	procs[42] = 2000 // brave exits, something unrelated gets PID 42

	out := g.Track([]Conn{{ID: "a", State: "TIME_WAIT", PID: -1, NoPID: "noproc"}})
	if len(out) != 1 || out[0].Comm != "brave" {
		t.Fatalf("name should still be carried, got %+v", out)
	}
	if out[0].PID != -1 || out[0].WasPID != 42 {
		t.Fatalf("recycled PID must not be presented as the owner, got %+v", out[0])
	}
}

// A ghost is promoted carrying a live PID; the owner then dies during the
// ghost window. The number has to be demoted on the tick that happens.
func TestGhostDemotesPIDWhenOwnerDiesDuringWindow(t *testing.T) {
	procs := map[int]uint64{42: 1000}
	fakeProcs(t, procs)

	g := NewGhosts(time.Minute)
	g.Track([]Conn{{ID: "a", State: "ESTABLISHED", PID: 42, Comm: "brave"}})

	out := g.Track(nil) // socket gone, promoted to ghost, owner still alive
	if len(out) != 1 || out[0].PID != 42 {
		t.Fatalf("ghost of a still-running process should keep its PID, got %+v", out)
	}

	delete(procs, 42)
	out = g.Track(nil)
	if len(out) != 1 || out[0].PID != -1 || out[0].WasPID != 42 {
		t.Fatalf("ghost should demote the PID once the owner exits, got %+v", out)
	}
}

// Resolve runs over the live set, and a ghost has left it — so a row promoted
// without a name used to carry "—" for its whole window even though the memo
// held the answer throughout. The retry has to happen on the ghost side.
func TestGhostResolvesNameAfterPromotion(t *testing.T) {
	procs := map[int]uint64{42: 1000}
	fakeProcs(t, procs)

	g := NewGhosts(time.Minute)
	g.Track([]Conn{{ID: "a", State: "ESTABLISHED", PID: 42, Comm: "python3", App: "python3 ⟨newco-revenue⟩"}})

	// The owner exits and the scanner cannot say who it was, so the row that
	// gets promoted is the anonymous one.
	delete(procs, 42)
	g.owners.mu.Lock()
	memo := g.owners.m["a"]
	g.owners.mu.Unlock()
	anon := Conn{ID: "a", State: "ESTABLISHED", PID: -1, NoPID: "gone"}
	g.mu.Lock()
	g.prev["a"] = anon // as if Resolve had missed it on the live tick
	g.mu.Unlock()

	out := g.Track(nil)
	if len(out) != 1 || out[0].State != "DISCONNECTED" {
		t.Fatalf("expected one ghost, got %+v", out)
	}
	if out[0].Comm != "python3" || out[0].App != memo.app {
		t.Fatalf("ghost should recover its name from the memo, got %+v", out[0])
	}
	if out[0].PID != -1 || out[0].WasPID != 42 || !out[0].Inherit {
		t.Fatalf("dead owner's PID belongs in WasPID, got %+v", out[0])
	}
}

// "denied" and "kernel" are different questions, and an old label answers
// neither: one has an owner we were refused, the other never had one at all.
func TestGhostDoesNotInventNames(t *testing.T) {
	for _, reason := range []string{"denied", "kernel", ""} {
		procs := map[int]uint64{42: 1000}
		fakeProcs(t, procs)

		g := NewGhosts(time.Minute)
		g.Track([]Conn{{ID: "a", State: "ESTABLISHED", PID: 42, Comm: "brave"}})
		out := g.Track([]Conn{{ID: "a", State: "ESTABLISHED", PID: -1, NoPID: reason}})
		if len(out) != 1 || out[0].Comm != "" {
			t.Fatalf("noPid=%q should not inherit a name, got %+v", reason, out)
		}
	}
}
