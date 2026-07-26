package main

import "testing"

func TestRulesAliasByIP(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("160.79.104.10", "Anthropic")
	cases := []struct{ raddr, want string }{
		{"160.79.104.10", "Anthropic"},
		{"160.79.104.11", ""}, // an exact-IP rule covers nothing else
	}
	for _, c := range cases {
		conn := Conn{RAddr: c.raddr}
		r.Apply(&conn)
		if conn.Alias != c.want {
			t.Errorf("Apply(%q) alias = %q, want %q", c.raddr, conn.Alias, c.want)
		}
	}
}

func TestRulesAliasByCIDR(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("160.79.104.0/21", "Anthropic")
	cases := []struct{ raddr, want string }{
		{"160.79.105.7", "Anthropic"},
		{"160.80.0.1", ""},
	}
	for _, c := range cases {
		conn := Conn{RAddr: c.raddr}
		r.Apply(&conn)
		if conn.Alias != c.want {
			t.Errorf("Apply(%q) alias = %q, want %q", c.raddr, conn.Alias, c.want)
		}
	}
}

func TestRulesMostSpecificNetworkWins(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("160.79.104.0/21", "RangeName")
	r.Set("160.79.104.10/32", "HostName")
	cases := []struct{ raddr, want string }{
		{"160.79.104.10", "HostName"},
		{"160.79.104.11", "RangeName"}, // neighbour keeps the range alias
	}
	for _, c := range cases {
		conn := Conn{RAddr: c.raddr}
		r.Apply(&conn)
		if conn.Alias != c.want {
			t.Errorf("Apply(%q) alias = %q, want %q", c.raddr, conn.Alias, c.want)
		}
	}
}

func TestRulesAliasByName(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("anthropic", "Claude")
	cases := []struct{ raddr, owner, host, want string }{
		{"1.2.3.4", "Anthropic PBC", "", "Claude"}, // case-insensitive substring
		{"1.2.3.4", "", "api.anthropic.com", "Claude"},
		{"1.2.3.4", "Google LLC", "dns.google", ""},
	}
	for _, c := range cases {
		conn := Conn{RAddr: c.raddr, Owner: c.owner, Host: c.host}
		r.Apply(&conn)
		if conn.Alias != c.want {
			t.Errorf("Apply(owner %q, host %q) alias = %q, want %q", c.owner, c.host, conn.Alias, c.want)
		}
	}
}

// An IP alias outranks whatever DNS or RDAP would have said, and AliasFor
// reports it before those lookups happen so they can be skipped entirely.
func TestRulesAliasByIPWinsAndSkipsLookups(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("1.2.3.4", "MyBox")
	r.Set("anthropic", "Claude")

	if got := r.AliasFor("1.2.3.4"); got != "MyBox" {
		t.Errorf("AliasFor(%q) = %q, want %q", "1.2.3.4", got, "MyBox")
	}
	// Name rules can't answer before the lookups, so AliasFor ignores them.
	if got := r.AliasFor("5.6.7.8"); got != "" {
		t.Errorf("AliasFor(%q) = %q, want %q", "5.6.7.8", got, "")
	}
	// Even with names present, the IP rule wins.
	conn := Conn{RAddr: "1.2.3.4", Host: "dns.google", Owner: "Google LLC"}
	r.Apply(&conn)
	if conn.Alias != "MyBox" {
		t.Errorf("Apply alias = %q, want %q", conn.Alias, "MyBox")
	}
}

func TestRulesAliasLocalAddress(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("192.168.1.0/24", "LAN")
	conn := Conn{LAddr: "192.168.1.5", RAddr: "1.2.3.4"}
	r.Apply(&conn)
	if conn.LAlias != "LAN" {
		t.Errorf("Apply lalias = %q, want %q", conn.LAlias, "LAN")
	}
	if conn.Alias != "" {
		t.Errorf("Apply alias = %q, want %q", conn.Alias, "")
	}
}

func TestRulesHide(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Hide("1.2.3.4", true)
	r.Hide("10.0.0.0/8", true)
	r.Hide("anthropic", true)
	cases := []struct {
		raddr, owner, host string
		want               bool
	}{
		{"1.2.3.4", "", "", true},
		{"10.1.2.3", "", "", true},
		{"5.6.7.8", "Anthropic PBC", "", true},
		{"5.6.7.8", "", "api.anthropic.com", true},
		{"5.6.7.8", "Google LLC", "dns.google", false},
	}
	for _, c := range cases {
		conn := Conn{RAddr: c.raddr, Owner: c.owner, Host: c.host}
		r.Apply(&conn)
		if conn.Hide != c.want {
			t.Errorf("Apply(%q, owner %q, host %q) hide = %v, want %v", c.raddr, c.owner, c.host, conn.Hide, c.want)
		}
	}

	// Unhiding removes the rule rather than remembering it as off.
	r.Hide("1.2.3.4", false)
	conn := Conn{RAddr: "1.2.3.4"}
	r.Apply(&conn)
	if conn.Hide {
		t.Errorf("after unhide, hide = true, want false")
	}
}

func TestRulesHideByAlias(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("1.2.3.4", "Anthropic")
	r.Hide("anthropic", true)
	conn := Conn{RAddr: "1.2.3.4"}
	r.Apply(&conn)
	if !conn.Hide {
		t.Errorf("Apply(%q) hide = false, want true", conn.RAddr)
	}
}

func TestRulesEmptyNameDeletesAlias(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("1.2.3.4", "X")
	r.Set("1.2.3.4", "")
	conn := Conn{RAddr: "1.2.3.4"}
	r.Apply(&conn)
	if conn.Alias != "" {
		t.Errorf("Apply(%q) alias = %q, want %q", conn.RAddr, conn.Alias, "")
	}
}

func TestRulesPersistence(t *testing.T) {
	dir := t.TempDir()
	r := NewRules(dir)
	r.Set("160.79.104.0/21", "Anthropic")
	r.Hide("1.2.3.4", true)

	r2 := NewRules(dir)
	conn := Conn{RAddr: "160.79.105.7"}
	r2.Apply(&conn)
	if conn.Alias != "Anthropic" {
		t.Errorf("reloaded Apply(%q) alias = %q, want %q", conn.RAddr, conn.Alias, "Anthropic")
	}
	hidden := Conn{RAddr: "1.2.3.4"}
	r2.Apply(&hidden)
	if !hidden.Hide {
		t.Errorf("reloaded Apply(%q) hide = false, want true", hidden.RAddr)
	}
}

func TestRulesReplaceIsCaseInsensitive(t *testing.T) {
	r := NewRules(t.TempDir())
	r.Set("Anthropic", "A")
	r.Set("anthropic", "B")
	aliases := r.Snapshot().Aliases
	if len(aliases) != 1 {
		t.Errorf("len(Snapshot().Aliases) = %d, want 1", len(aliases))
	}
	if len(aliases) > 0 && aliases[0].Name != "B" {
		t.Errorf("alias name = %q, want %q", aliases[0].Name, "B")
	}
}
