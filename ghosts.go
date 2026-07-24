package main

import (
	"sync"
	"time"
)

// ghostTTL is how long a vanished ESTABLISHED connection lingers in the
// table as a DISCONNECTED "ghost" after the kernel drops its socket.
const ghostTTL = 30 * time.Second

// Ghosts remembers connections that were ESTABLISHED and then disappeared,
// re-emitting them as state "DISCONNECTED" for a short window. Tracking
// runs on every tick — even with no browser open — so a connection that
// dies the instant you open the UI is already a ghost by the first paint.
type Ghosts struct {
	mu   sync.Mutex
	prev map[string]Conn  // live conns from the previous tick
	dead map[string]ghost // id -> ghost currently held
}

type ghost struct {
	c     Conn
	since time.Time
}

func NewGhosts() *Ghosts {
	return &Ghosts{prev: map[string]Conn{}, dead: map[string]ghost{}}
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
		if now.Sub(gh.since) > ghostTTL {
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
