package main

import (
	"net/netip"
	"strings"
	"testing"
)

// The firewall command is the one place a hostile string could reach a
// privileged process, so pin its exact shape.
func TestUFWArgs(t *testing.T) {
	cases := []struct {
		ip   string
		undo bool
		want string
	}{
		{"1.2.3.4", false, "ufw insert 1 deny out to 1.2.3.4"},
		{"1.2.3.4", true, "ufw delete deny out to 1.2.3.4"},
		{"2606:4700::1", false, "ufw insert 1 deny out to 2606:4700::1"},
		// v4-mapped v6 must render as the v4 address ufw understands,
		// not as ::ffff:1.2.3.4.
		{"::ffff:1.2.3.4", false, "ufw insert 1 deny out to 1.2.3.4"},
	}
	for _, c := range cases {
		addr, err := netip.ParseAddr(c.ip)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", c.ip, err)
		}
		got := strings.Join(ufwArgs(addr.Unmap(), c.undo), " ")
		if got != c.want {
			t.Errorf("ufwArgs(%q, undo=%v) = %q, want %q", c.ip, c.undo, got, c.want)
		}
	}
}

// Anything that is not a bare address must be refused before it can reach
// the command builder at all. These are the strings the handler rejects.
func TestBlockTargetRejected(t *testing.T) {
	bad := []string{
		"1.2.3.4; rm -rf /", "1.2.3.4 --insert", "--force", "any",
		"evil.com", "1.2.3.0/24", "$(id)", "`id`", "", " ", "0.0.0.0", "::",
		"1.2.3.4\n5.6.7.8",
	}
	for _, s := range bad {
		addr, err := netip.ParseAddr(s)
		if err == nil && !addr.IsUnspecified() {
			t.Errorf("%q was accepted as a block target, want rejected", s)
		}
	}
}
