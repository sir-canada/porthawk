package main

import (
	"testing"
	"time"
)

// A socket with an inode that no process holds is a race only for as long
// as an exiting process could explain it. NFS's lockd keeps four such
// sockets for the life of the mount; calling those "gone" on every tick
// both mislabels them and buries the real races in the count.
func TestUnownedReason(t *testing.T) {
	now := time.Now()
	s := NewScanner()
	s.unowned[1] = now                     // first seen this tick
	s.unowned[2] = now.Add(-kernelUnowned) // held exactly long enough
	s.unowned[3] = now.Add(-time.Hour)     // held since the mount

	for _, tc := range []struct {
		name  string
		inode uint64
		want  string
	}{
		{"just vanished", 1, "gone"},
		{"at the threshold", 2, "kernel"},
		{"permanent", 3, "kernel"},
		{"never seen unowned", 9, "gone"},
	} {
		if got := s.unownedReason(tc.inode, now); got != tc.want {
			t.Errorf("%s: unownedReason(%d) = %q, want %q", tc.name, tc.inode, got, tc.want)
		}
	}

	// Being refused a process's fds outranks age: a socket we are not
	// allowed to see the owner of looks exactly like one that has none.
	s.blocked = 1
	if got := s.unownedReason(3, now); got != "denied" {
		t.Errorf("with a blocked walk, want %q, got %q", "denied", got)
	}
}
