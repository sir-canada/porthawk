package main

import (
	"bufio"
	"bytes"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"github.com/phuslu/iploc"
)

var (
	geoMu    sync.Mutex
	geoCache = map[netip.Addr][2]string{} // addr -> {cc, flag}
)

var (
	vpnMu    sync.Mutex
	vpnCache = map[netip.Addr]bool{} // addr -> reachable over VPN/tunnel iface
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
	if routeIsVPN(a) {
		return "", "🛡"
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

// routeIsVPN reports whether a is reachable over a VPN/tunnel network
// interface, by inspecting `ip route get <a>` for its `dev <name>` token.
// Results are cached per address. Missing `ip` binary, command errors, or
// an absent dev token all yield false.
func routeIsVPN(a netip.Addr) bool {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	if v, ok := vpnCache[a]; ok {
		return v
	}
	res := false
	out, err := exec.Command("ip", "route", "get", a.String()).Output()
	if err == nil {
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "dev" {
					res = ifaceIsVPN(f[i+1])
					break
				}
			}
			if res {
				break
			}
		}
	}
	vpnCache[a] = res
	return res
}

// ifaceIsVPN reports whether an interface name looks like a VPN/tunnel device.
func ifaceIsVPN(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"zt", "tun", "tap", "wg", "tailscale", "nord", "proton", "gpd", "ppp", "wt", "utun"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}
