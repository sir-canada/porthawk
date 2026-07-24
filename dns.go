package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver does cached, toggleable reverse-DNS lookups server-side.
type Resolver struct {
	enabled atomic.Bool
	mu      sync.Mutex
	cache   map[string]dnsEntry
	queue   chan string
	queued  map[string]bool
}

type dnsEntry struct {
	host string // "" = negative result
	at   time.Time
}

const (
	dnsTTL    = time.Hour
	dnsNegTTL = 10 * time.Minute
)

func NewResolver(enabled bool) *Resolver {
	r := &Resolver{
		cache:  make(map[string]dnsEntry),
		queue:  make(chan string, 1024),
		queued: make(map[string]bool),
	}
	r.enabled.Store(enabled)
	return r
}

func (r *Resolver) Start(ctx context.Context) {
	for i := 0; i < 24; i++ {
		go r.worker(ctx)
	}
}

func (r *Resolver) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-r.queue:
			lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			names, err := net.DefaultResolver.LookupAddr(lctx, ip)
			cancel()
			host := ""
			if err == nil && len(names) > 0 {
				host = strings.TrimSuffix(names[0], ".")
			}
			r.mu.Lock()
			r.cache[ip] = dnsEntry{host, time.Now()}
			delete(r.queued, ip)
			r.mu.Unlock()
		}
	}
}

// Lookup returns the cached hostname ("" if none) and, when enabled,
// enqueues unresolved addresses. Never blocks.
func (r *Resolver) Lookup(ip string) string {
	if ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "invalid IP" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[ip]; ok {
		ttl := dnsTTL
		if e.host == "" {
			ttl = dnsNegTTL
		}
		if time.Since(e.at) < ttl {
			return e.host
		}
	}
	if r.enabled.Load() && !r.queued[ip] {
		select {
		case r.queue <- ip:
			r.queued[ip] = true
		default: // queue full, retry next tick
		}
	}
	return ""
}

func (r *Resolver) SetEnabled(v bool) { r.enabled.Store(v) }
func (r *Resolver) Enabled() bool     { return r.enabled.Load() }
