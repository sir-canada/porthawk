package main

import (
	"sync"
	"time"
)

// Bounds for the ghost window. Zero is a real setting — it means dead
// sockets vanish the moment the kernel drops them — so the lower bound is
// not a minimum duration but a floor on the number itself.
const (
	defaultGhostTTL = 45 * time.Second
	maxGhostTTL     = 600 * time.Second
)

// Ghosts remembers connections that were ESTABLISHED and then disappeared,
// re-emitting them as state "DISCONNECTED" for a short window. Tracking
// runs on every tick — even with no browser open — so a connection that
// dies the instant you open the UI is already a ghost by the first paint.
type Ghosts struct {
	mu   sync.Mutex
	ttl  time.Duration    // how long a ghost lingers; 0 disables ghosting
	prev map[string]Conn  // live conns from the previous tick
	dead map[string]ghost // id -> ghost currently held
}

type ghost struct {
	c     Conn
	since time.Time
}

func NewGhosts(ttl time.Duration) *Ghosts {
	return &Ghosts{
		ttl:  clampGhostTTL(ttl),
		prev: map[string]Conn{},
		dead: map[string]ghost{},
	}
}

func clampGhostTTL(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d > maxGhostTTL {
		return maxGhostTTL
	}
	return d
}

// SetTTL changes the window live. Track compares against the current value
// on every tick, so a shortened window expires ghosts already being held
// on the next tick rather than only applying to future ones.
func (g *Ghosts) SetTTL(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ttl = clampGhostTTL(d)
}

func (g *Ghosts) TTL() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ttl
}

// Track diffs the current live set against the previous tick, promotes
// vanished ESTABLISHED connections to ghosts, expires stale ones, and
// returns live + surviving ghosts. Only ESTABLISHED sockets are ghosted,
// so ordinary TCP churn (TIME_WAIT, SYN_SENT, ...) never floods the table.
func (g *Ghosts) Track(live []Conn) []Conn {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()

	liveIDs := make(map[string]bool, len(live))
	for _, c := range live {
		liveIDs[c.ID] = true
	}
	// The kernel drops a socket's owner the moment the process exits, but
	// the socket outlives it by a tick or more — and then the row is
	// promoted to a ghost from that last, already-stripped copy. The result
	// was that a connection kept its name right up until it died and then
	// lost it, which is precisely backwards: the corpse is the row you most
	// want a name on. So carry the name across from the previous tick.
	//
	// Only for "gone", which is the one reason that means "this socket had
	// an owner and that owner exited" — an inode we were refused, one the
	// kernel never gave an owner, and one that never had a name are all
	// different questions, and none of them are answered by an old label.
	// The PID is not carried: that number belongs to a process that is not
	// there any more, and pasting it into kill(1) would be a lie.
	for i := range live {
		c := &live[i]
		if c.Comm != "" || c.NoPID != "gone" {
			continue
		}
		if p, ok := g.prev[c.ID]; ok && p.Comm != "" {
			c.Comm, c.App = p.Comm, p.App
		}
	}
	// Ghosting turned off: drop anything still held and keep the prev set
	// current, so turning it back on starts diffing from this tick instead
	// of resurrecting everything that died while it was off.
	if g.ttl == 0 {
		clear(g.dead)
		g.prev = make(map[string]Conn, len(live))
		for _, c := range live {
			g.prev[c.ID] = c
		}
		return live
	}
	// A live connection cancels any ghost of the same id (it came back).
	for id := range liveIDs {
		delete(g.dead, id)
	}
	// Promote: ESTABLISHED last tick, gone now, not already held.
	for id, c := range g.prev {
		if liveIDs[id] || c.State != "ESTABLISHED" {
			continue
		}
		if _, held := g.dead[id]; held {
			continue
		}
		gc := c
		gc.State = "DISCONNECTED"
		gc.UpRate, gc.DownRate = 0, 0 // no live traffic on a dead socket
		g.dead[id] = ghost{c: gc, since: now}
	}
	// Expire and append survivors.
	out := live
	for id, gh := range g.dead {
		if now.Sub(gh.since) > g.ttl {
			delete(g.dead, id)
			continue
		}
		out = append(out, gh.c)
	}
	// Remember this tick's live set for the next diff.
	g.prev = make(map[string]Conn, len(live))
	for _, c := range live {
		g.prev[c.ID] = c
	}
	return out
}
