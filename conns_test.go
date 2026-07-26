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

// Age alone cannot mean "kernel". A socket whose owner exits keeps its inode
// for as long as the peer leaves the connection up — minutes on a real link —
// so the age test on its own files every one of them as kernel-internal, and
// "kernel" is the reason that is never resolved from LastOwners. The result is
// an anonymous row for exactly the socket that has a name to show.
func TestOnceOwnedSocketIsNeverKernel(t *testing.T) {
	now := time.Now()
	s := NewScanner()
	s.unowned[7] = now.Add(-time.Hour)
	s.everOwned[7] = true

	if got := s.unownedReason(7, now); got != "gone" {
		t.Errorf("a socket we once attributed is gone, not kernel-owned: got %q", got)
	}
	if s.kernelOwned(7, now) {
		t.Error("kernelOwned should be false for an inode a process once held")
	}
	// The same age on an inode nothing ever held is still kernel-owned.
	s.unowned[8] = now.Add(-time.Hour)
	if !s.kernelOwned(8, now) {
		t.Error("an inode no process ever held should still age into kernel-owned")
	}
}

// Attribution and ageing share one pass over the scan, and both maps are
// bounded by the live inode set: an inode that leaves the socket table takes
// its history with it, or a long-running porthawk leaks one entry per socket
// it ever saw. Regaining an owner also clears the age, so a walk race does not
// leave a socket permanently pre-aged.
func TestScannerInodeMapsArePruned(t *testing.T) {
	s := NewScanner()
	s.unowned[1] = time.Now().Add(-time.Hour)
	s.everOwned[1] = true
	s.everOwned[2] = true

	s.Scan() // neither inode is in this machine's socket tables

	if _, ok := s.unowned[1]; ok {
		t.Error("unowned should not retain an inode that has left the socket table")
	}
	if s.everOwned[1] || s.everOwned[2] {
		t.Error("everOwned should not retain inodes that have left the socket table")
	}
}
