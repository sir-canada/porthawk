package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// parseProcStart is readProcStart's parsing half, exercised against literal
// stat contents. The file cannot be split from the left: field 2 is the comm,
// it is parenthesised, and it can contain spaces and closing parens.
func parseProcStart(t *testing.T, stat string) (uint64, bool) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(p, []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	return readProcStatFile(p)
}

// A plain comm, and the field-22 offset is what we claim it is.
func TestProcStartPlain(t *testing.T) {
	fields := make([]string, 0, 30)
	fields = append(fields, "7", "(brave)")
	for i := 3; i <= 30; i++ {
		if i == 22 {
			fields = append(fields, "918273")
			continue
		}
		fields = append(fields, "0")
	}
	got, ok := parseProcStart(t, strings.Join(fields, " ")+"\n")
	if !ok || got != 918273 {
		t.Fatalf("got %d, %v; want 918273, true", got, ok)
	}
}

// Firefox names threads "(Web Content)"; a process can also put a ')' in its
// own name. Splitting on the last ')' is what makes both parse.
func TestProcStartCommWithSpacesAndParens(t *testing.T) {
	for _, comm := range []string{"(Web Content)", "(evil) name)", "(a b c)"} {
		fields := make([]string, 0, 30)
		fields = append(fields, "7", comm)
		for i := 3; i <= 30; i++ {
			if i == 22 {
				fields = append(fields, "555")
				continue
			}
			fields = append(fields, "0")
		}
		got, ok := parseProcStart(t, strings.Join(fields, " ")+"\n")
		if !ok || got != 555 {
			t.Fatalf("comm=%q: got %d, %v; want 555, true", comm, got, ok)
		}
	}
}

func TestProcStartRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "7 (brave)", "no parens here", "7 (brave) x"} {
		if _, ok := parseProcStart(t, s); ok {
			t.Fatalf("%q should not parse", s)
		}
	}
}

// The memo is only as good as its start time: without one, a PID cannot be
// vouched for and must not be presented as live.
func TestOwnerMemoWithoutStartIsNeverAlive(t *testing.T) {
	fakeProcs(t, map[int]uint64{42: 0})
	if (ownerMemo{pid: 42, start: 0}).alive() {
		t.Fatal("a memo with no start time must not report alive")
	}
}

func TestLastOwnersExpires(t *testing.T) {
	fakeProcs(t, map[int]uint64{42: 1000})
	l := NewLastOwners()
	t0 := time.Now()
	l.Record([]Conn{{ID: "a", PID: 42, Comm: "brave"}}, t0)

	c := Conn{ID: "a", PID: -1}
	if !l.Resolve(&c) {
		t.Fatal("fresh memo should resolve")
	}
	// Recording a later tick with the socket absent ages the entry out.
	l.Record(nil, t0.Add(lastOwnerTTL+time.Second))
	c2 := Conn{ID: "a", PID: -1}
	if l.Resolve(&c2) {
		t.Fatal("memo past its TTL should be forgotten")
	}
}
