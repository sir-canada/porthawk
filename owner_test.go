package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseCymruASName(t *testing.T) {
	cases := []struct{ txt, want string }{
		// "<handle> - <organisation>, <CC>": the organisation is the useful
		// part, and the country code is not part of the name.
		{"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US", "Google LLC"},
		{"399358 | US | arin | 2023-09-20 | ANTHROPIC - Anthropic, PBC, US", "Anthropic, PBC"},
		// No " - " separator: the whole description is the name, minus the
		// trailing country code.
		{"9009 | GB | ripencc | 2014-11-25 | M247, RO", "M247"},
		{"4134 | CN | apnic | 2001-06-28 | CHINANET-BACKBONE No.31,Jin-rong Street, CN",
			"CHINANET-BACKBONE No.31,Jin-rong Street"},
		// A trailing lowercase or longer word is part of the name, not a
		// country code.
		{"1 | US | arin | 2000-01-01 | EXAMPLE - Example, Inc", "Example, Inc"},
		{"", ""},
		{"64500 | US | arin | 2020-01-01 | ", ""},
	}
	for _, c := range cases {
		if got := parseCymruASName(c.txt); got != c.want {
			t.Errorf("parseCymruASName(%q) = %q, want %q", c.txt, got, c.want)
		}
	}
	// Names are capped in runes, not bytes.
	long := "1 | US | arin | 2020-01-01 | " + strings.Repeat("ä", 50)
	if got := parseCymruASName(long); got != strings.Repeat("ä", 40) {
		t.Errorf("parseCymruASName(long) = %q, want 40 runes", got)
	}
}

func TestParseCymruOrigin(t *testing.T) {
	addr := netip.MustParseAddr("149.154.167.92")

	// Several announcements can cover one address; the most specific route
	// is the one traffic actually follows.
	txts := []string{
		"62041 | 149.154.166.0/23 | AG | ripencc | 2011-08-10",
		"62041 | 149.154.167.0/24 | AG | ripencc | 2011-08-10",
	}
	p, asn, ok := parseCymruOrigin(txts, addr)
	if !ok || p.String() != "149.154.167.0/24" || asn != 62041 {
		t.Errorf("parseCymruOrigin = %v/%v/%v, want 149.154.167.0/24, 62041, true", p, asn, ok)
	}

	// A prefix that doesn't contain the address is ignored.
	if _, _, ok := parseCymruOrigin([]string{"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"}, addr); ok {
		t.Error("parseCymruOrigin accepted a prefix not containing the address")
	}

	// Multi-origin announcements list several AS numbers in one field.
	p, asn, ok = parseCymruOrigin(
		[]string{"1234 5678 | 149.154.167.0/24 | AG | ripencc | 2011-08-10"}, addr)
	if !ok || asn != 1234 {
		t.Errorf("parseCymruOrigin multi-origin = %v/%v/%v, want asn 1234", p, asn, ok)
	}

	// Malformed answers yield nothing rather than panicking.
	for _, bad := range [][]string{
		nil,
		{""},
		{"no pipes here"},
		{"notanumber | 149.154.167.0/24 | AG | ripencc | 2011-08-10"},
		{"62041 | notaprefix | AG | ripencc | 2011-08-10"},
	} {
		if _, _, ok := parseCymruOrigin(bad, addr); ok {
			t.Errorf("parseCymruOrigin(%q) = ok, want not ok", bad)
		}
	}
}

func TestCymruOriginName(t *testing.T) {
	cases := []struct{ ip, want string }{
		{"8.8.8.8", "8.8.8.8.origin.asn.cymru.com"},
		{"160.79.104.10", "10.104.79.160.origin.asn.cymru.com"},
		// v6: reversed nibbles, all zeroes padded out, under origin6.
		{"2001:4860::8888", "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"},
	}
	for _, c := range cases {
		if got := cymruOriginName(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("cymruOriginName(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestOwnerAddr(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"2001:4860:4860::8888", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"169.254.1.1", false},
		{"224.0.0.1", false},
		{"0.0.0.0", false},
		{"not an ip", false},
		{"", false},
	}
	for _, c := range cases {
		if _, got := ownerAddr(c.ip); got != c.want {
			t.Errorf("ownerAddr(%q) ok = %v, want %v", c.ip, got, c.want)
		}
	}
}

// A cached name must never be shadowed by a later failure, and expiry must
// be per entry rather than a single global TTL.
func TestOwnerCachePrecedence(t *testing.T) {
	o := NewOwner(t.TempDir(), false)
	ip := "160.79.104.10"
	a := netip.MustParseAddr(ip)

	o.put(netip.MustParsePrefix("160.79.104.0/23"), "Anthropic, PBC", ownerTTL)
	o.put(netip.MustParsePrefix("160.79.104.0/24"), "", ownerFailTTL) // more specific, but a failure
	if got := o.Lookup(ip); got != "Anthropic, PBC" {
		t.Errorf("Lookup = %q, want the known owner to beat the failed probe", got)
	}
	if got := o.Prefix(ip); got != "160.79.104.0/23" {
		t.Errorf("Prefix = %q, want 160.79.104.0/23", got)
	}

	// An expired entry is not returned.
	o.put(netip.MustParsePrefix("8.8.8.0/24"), "Google LLC", -time.Minute)
	if got := o.Lookup("8.8.8.8"); got != "" {
		t.Errorf("Lookup of expired entry = %q, want %q", got, "")
	}
	if _, _, ok := o.find(a.Next()); !ok {
		t.Error("find lost a live entry")
	}
}
