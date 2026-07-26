package main

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcStat holds per-process traffic. KB values are cumulative since
// monitoring start (nethogs -v1); rates derived from refresh deltas.
type ProcStat struct {
	Name     string  `json:"name"`
	App      string  `json:"app"`
	SentKB   float64 `json:"up"`
	RecvKB   float64 `json:"down"`
	SentRate float64 `json:"upRate"`   // KB/s
	RecvRate float64 `json:"downRate"` // KB/s
	lastSeen time.Time
	// last raw cumulative values reported by the current nethogs run
	rawSent, rawRecv float64
}

// Hogs runs nethogs in trace mode and aggregates per-PID traffic.
type Hogs struct {
	mu    sync.Mutex
	why   string // non-empty: per-process totals are degraded, and this is why
	procs map[int]*ProcStat
	last  time.Time // time of previous refresh block
	// pending block being parsed
	block map[int]struct {
		name       string
		sent, recv float64
	}
}

func NewHogs() *Hogs {
	return &Hogs{procs: make(map[int]*ProcStat)}
}

// Why reports why per-process totals are missing or degraded, "" when
// nethogs is running normally.
func (h *Hogs) Why() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.why
}

func (h *Hogs) setWhy(s string) {
	h.mu.Lock()
	h.why = s
	h.mu.Unlock()
}

// Run spawns nethogs and keeps it alive. Blocks; call in a goroutine.
func (h *Hogs) Run(ctx context.Context) {
	// An absent optional dependency is a permanent condition, not a crash
	// to retry. Retrying it every 3 s writes tens of thousands of identical
	// lines to the journal per day and cannot ever succeed. Say it once,
	// report it through the UI like the other optional subsystem, stop.
	if _, err := exec.LookPath("nethogs"); err != nil {
		h.setWhy("nethogs is not installed, so per-process traffic totals are unavailable")
		log.Print("nethogs not found in PATH — per-process traffic totals disabled")
		log.Print("nethogs: install it and restart porthawk to enable them")
		return
	}
	// A real crash is worth retrying, but not at a fixed 3 s forever: back
	// off to a couple of minutes so a persistently broken nethogs is a
	// trickle rather than a flood.
	const minDelay, maxDelay = 3 * time.Second, 2 * time.Minute
	delay := minDelay
	for ctx.Err() == nil {
		started := time.Now()
		err := h.run(ctx)
		if ctx.Err() != nil {
			return
		}
		// A run that survived a while was healthy; don't punish the next
		// failure with a delay compounded from an unrelated older one.
		if time.Since(started) > 30*time.Second {
			delay = minDelay
		}
		h.setWhy("nethogs keeps exiting (" + errText(err) + "); retrying every " + delay.String())
		log.Printf("nethogs exited (%v), restarting in %s", err, delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		if delay < maxDelay {
			if delay *= 2; delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

// run is one nethogs lifetime: start it, parse until it dies, report why.
// -t tracemode, -v1 cumulative KB, -d1 1s refresh, -a all ifaces, -C tcp+udp.
func (h *Hogs) run(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "nethogs", "-t", "-v1", "-d", "1", "-a", "-C")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	h.setWhy("") // it is up; clear any previous complaint
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		h.line(sc.Text())
	}
	return cmd.Wait()
}

func errText(err error) string {
	if err == nil {
		return "no error reported"
	}
	return err.Error()
}

// line parses one tracemode line. Entry format:
//
//	<program>/<pid>/<uid>\t<sent>\t<received>
//
// pid/uid sit at the END of the program string, which may itself
// contain slashes — parse from the right. "Refreshing:" delimits blocks.
func (h *Hogs) line(l string) {
	if strings.HasPrefix(l, "Refreshing:") {
		h.commit()
		return
	}
	f := strings.Split(l, "\t")
	if len(f) != 3 {
		return // banner/noise
	}
	sent, err1 := strconv.ParseFloat(f[1], 64)
	recv, err2 := strconv.ParseFloat(f[2], 64)
	if err1 != nil || err2 != nil {
		return
	}
	prog := f[0]
	i := strings.LastIndexByte(prog, '/')
	if i < 0 {
		return
	}
	j := strings.LastIndexByte(prog[:i], '/')
	if j < 0 {
		return
	}
	pid, err := strconv.Atoi(prog[j+1 : i])
	if err != nil {
		return
	}
	name := prog[:j]
	if k := strings.LastIndexByte(name, '/'); k >= 0 && k < len(name)-1 {
		name = name[k+1:] // basename for display
	}

	h.mu.Lock()
	if h.block == nil {
		h.block = make(map[int]struct {
			name       string
			sent, recv float64
		})
	}
	h.block[pid] = struct {
		name       string
		sent, recv float64
	}{name, sent, recv}
	h.mu.Unlock()
}

// commit applies a completed refresh block: totals are absolute
// (cumulative), rates = delta / elapsed.
func (h *Hogs) commit() {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	dt := now.Sub(h.last).Seconds()
	if dt <= 0 || dt > 10 {
		dt = 1
	}
	seen := make(map[int]bool, len(h.block))
	for pid, b := range h.block {
		seen[pid] = true
		p := h.procs[pid]
		if p == nil {
			p = &ProcStat{Name: b.name}
			h.procs[pid] = p
		}
		dSent := b.sent - p.rawSent
		if dSent < 0 { // nethogs restarted, counters reset
			dSent = b.sent
		}
		dRecv := b.recv - p.rawRecv
		if dRecv < 0 {
			dRecv = b.recv
		}
		p.rawSent, p.rawRecv = b.sent, b.recv
		p.SentKB += dSent // totals survive restarts: accumulate deltas
		p.RecvKB += dRecv
		p.SentRate = dSent / dt
		p.RecvRate = dRecv / dt
		p.lastSeen = now
	}
	// zero rates for processes absent from this block; expire after 60s idle
	for pid, p := range h.procs {
		if !seen[pid] {
			p.SentRate, p.RecvRate = 0, 0
			if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err != nil {
				delete(h.procs, pid) // process gone from system
			} else if now.Sub(p.lastSeen) > 60*time.Second && p.SentKB == 0 && p.RecvKB == 0 {
				delete(h.procs, pid)
			}
		}
	}
	h.block = nil
	h.last = now
}

// Snapshot returns a copy of per-PID stats plus global totals.
func (h *Hogs) Snapshot() (map[int]ProcStat, ProcStat) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[int]ProcStat, len(h.procs))
	var tot ProcStat
	for pid, p := range h.procs {
		out[pid] = *p
		tot.SentKB += p.SentKB
		tot.RecvKB += p.RecvKB
		tot.SentRate += p.SentRate
		tot.RecvRate += p.RecvRate
	}
	return out, tot
}
