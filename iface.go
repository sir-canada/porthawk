package main

import (
	"net"
	"sync"
	"time"
)

// Ifaces answers "is this address one of mine, and if so which adapter is
// it on?". An address the kernel assigned to a local interface already has
// a true, local, zero-cost name — wlan0 — and naming it that way is both
// more accurate and more useful than the machine's hostname, which reverse
// DNS hands back identically for every interface on a multi-homed box.
//
// Purely local: reads the interface table, never touches the network, so
// it needs no toggle and no enable/disable plumbing.
type Ifaces struct {
	mu sync.RWMutex
	m  map[string]string // address (no zone) -> interface name
	at time.Time
}

// ifaceTTL bounds how stale the address->adapter map can get. Interfaces
// come and go (VPN up, DHCP renew, docker0 appearing), but not once a
// second, and enumerating them is a syscall walk we don't want on every
// tick of the broadcast loop.
const ifaceTTL = 10 * time.Second

func NewIfaces() *Ifaces {
	f := &Ifaces{m: make(map[string]string)}
	f.refresh()
	return f
}

// Name returns the interface that owns ip, or "" if the address is not
// ours. Never blocks on the network.
func (f *Ifaces) Name(ip string) string {
	if ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "invalid IP" {
		return ""
	}
	f.mu.RLock()
	stale := time.Since(f.at) > ifaceTTL
	name := f.m[ip]
	f.mu.RUnlock()
	if !stale {
		return name
	}
	f.refresh()
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.m[ip]
}

// refresh rebuilds the map from the kernel's interface table. On error the
// previous map is kept: a transient failure should not make every local
// address suddenly lose its name.
func (f *Ifaces) refresh() {
	ifs, err := net.Interfaces()
	if err != nil {
		f.mu.Lock()
		f.at = time.Now() // don't hammer a failing syscall every tick
		f.mu.Unlock()
		return
	}
	fresh := make(map[string]string, 16)
	for _, in := range ifs {
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			// Match the string form the scanner produces: v4-mapped v6 is
			// already unmapped there, and link-local addresses arrive
			// without a %zone suffix.
			ip := n.IP
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			fresh[ip.String()] = in.Name
		}
	}
	f.mu.Lock()
	f.m = fresh
	f.at = time.Now()
	f.mu.Unlock()
}
