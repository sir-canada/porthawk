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
