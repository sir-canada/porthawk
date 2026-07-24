package main

import (
	"net/netip"
	"sync"

	"github.com/phuslu/iploc"
)

var (
	geoMu    sync.Mutex
	geoCache = map[netip.Addr][2]string{} // addr -> {cc, flag}
)

// geoLookup returns ISO country code + flag emoji for a remote address.
// Special addresses get symbolic flags instead of countries.
func geoLookup(a netip.Addr) (string, string) {
	if !a.IsValid() || a.IsUnspecified() {
		return "", "" // listener / no peer
	}
	if a.IsLoopback() {
		return "", "🔁"
	}
	if a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() {
		return "", "🏠"
	}
	geoMu.Lock()
	defer geoMu.Unlock()
	if v, ok := geoCache[a]; ok {
		return v[0], v[1]
	}
	cc := iploc.IPCountry(a)
	flag := "🏳️"
	if len(cc) == 2 && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z' {
		// regional indicator symbols: 'A' -> U+1F1E6
		flag = string(0x1F1E6+rune(cc[0]-'A')) + string(0x1F1E6+rune(cc[1]-'A'))
	} else {
		cc = ""
	}
	geoCache[a] = [2]string{cc, flag}
	return cc, flag
}
