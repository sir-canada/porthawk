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
	mu     sync.Mutex
	ttl    time.Duration    // how long a ghost lingers; 0 disables ghosting
	prev   map[string]Conn  // live conns from the previous tick
	dead   map[string]ghost // id -> ghost currently held
	owners *LastOwners      // 4-tuple -> last process seen owning it
}

type ghost struct {
	c     Conn
	since time.Time
}

func NewGhosts(ttl time.Duration) *Ghosts {
	return &Ghosts{
		ttl:    clampGhostTTL(ttl),
		prev:   map[string]Conn{},
		dead:   map[string]ghost{},
		owners: NewLastOwners(),
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
	// Remember who owns what, then hand names back to the sockets the kernel
	// has stopped attributing. Record runs first so a socket that loses its
	// owner this very tick is resolved from an entry written moments ago.
	g.owners.Record(live, now)

	// The kernel drops a socket's owner the moment the process exits, but
	// the socket outlives it by a tick or more — and then the row is
	// promoted to a ghost from that last, already-stripped copy. The result
	// was that a connection kept its name right up until it died and then
	// lost it, which is precisely backwards: the corpse is the row you most
	// want a name on. So carry the attribution across from LastOwners.
	//
	// Two of the four reasons are answerable this way, and two are not:
	//
	//   "gone"   the owner existed and exited. The socket is the same socket.
	//   "noproc" TIME_WAIT and friends: the kernel keeps no process for these,
	//            but a TIME_WAIT socket is the *same 4-tuple* that was
	//            ESTABLISHED a second earlier, so the memo is an identity
	//            match rather than a guess. This is the common case by volume
	//            and the one that leaves a screen full of anonymous rows.
	//
	//   "denied" we were refused the owner's fds. The owner is right there and
	//            readable in principle; papering over that with an old label
	//            hides a live permissions problem instead of reporting it.
	//   "kernel" no process holds it and none ever did. There is nothing to
	//            carry, and inventing one would be a fiction.
	for i := range live {
		c := &live[i]
		if c.Comm != "" || (c.NoPID != "gone" && c.NoPID != "noproc") {
			continue
		}
		g.owners.Resolve(c)
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
		// Resolve runs over the live set, and a ghost has by definition left
		// it — so a row promoted without a name never got a second chance at
		// one, and carried "—" for the whole window even when the memo held
		// the answer the entire time. Retry here. The memo outlives the
		// socket by design, and the miss at promotion is often a matter of
		// ordering rather than ignorance.
		if gh.c.Comm == "" && (gh.c.NoPID == "gone" || gh.c.NoPID == "noproc") {
			g.owners.Resolve(&gh.c)
		}
		// A ghost is promoted carrying the PID it had while alive, and the
		// process that owned it very often dies during the window — that is
		// usually *why* the socket died. So recheck on every tick, not just at
		// promotion, and demote the number the moment it stops naming that
		// process, rather than letting a corpse advertise a PID the kernel may
		// already have handed to something else.
		g.owners.Verify(&gh.c)
		g.dead[id] = gh
		out = append(out, gh.c)
	}
	// Remember this tick's live set for the next diff.
	g.prev = make(map[string]Conn, len(live))
	for _, c := range live {
		g.prev[c.ID] = c
	}
	return out
}
