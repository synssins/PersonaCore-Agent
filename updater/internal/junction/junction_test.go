//go:build windows

package junction

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndReadTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "v1")
	link := filepath.Join(root, "current")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "marker.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Create(link, target); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Walk through the junction and see the marker.
	got, err := os.ReadFile(filepath.Join(link, "marker.txt"))
	if err != nil {
		t.Fatalf("read via junction: %v", err)
	}
	if string(got) != "v1" {
		t.Fatalf("marker: got %q", got)
	}
	// ReadTarget should return the absolute target path.
	rt, err := ReadTarget(link)
	if err != nil {
		t.Fatalf("ReadTarget: %v", err)
	}
	absTarget, _ := filepath.Abs(target)
	if !equalIgnoreCase(rt, absTarget) {
		t.Fatalf("ReadTarget: got %q want %q", rt, absTarget)
	}
}

func TestReplace_SwapsAtomically(t *testing.T) {
	root := t.TempDir()
	v1 := filepath.Join(root, "v1")
	v2 := filepath.Join(root, "v2")
	link := filepath.Join(root, "current")
	for _, d := range []string{v1, v2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(v1, "which.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v2, "which.txt"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Create(link, v1); err != nil {
		t.Fatal(err)
	}
	if err := Replace(link, v2); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(link, "which.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Fatalf("after Replace, expected v2, got %q", got)
	}
	// Ensure v1 still exists — Replace must not touch the old target.
	if _, err := os.Stat(v1); err != nil {
		t.Fatalf("v1 should still exist: %v", err)
	}
}

func TestReplace_CreatesWhenMissing(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "v1")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "current")
	if err := Replace(link, target); err != nil {
		t.Fatalf("Replace (missing): %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal(err)
	}
}

// TestReplace_AtomicNeverLeavesGoneState proves the SPEC-06 rule:
//
//	"Updater failure MUST leave the previous `current` junction untouched."
//
// The previous implementation of Replace did os.Remove(old) followed by
// os.Rename(new, old); a crash between those two calls left `current`
// permanently gone. The new implementation collapses the two steps into
// a single MoveFileEx(MOVEFILE_REPLACE_EXISTING) via `cmd.exe /c move
// /Y`, which is atomic at the filesystem level for reparse points on
// the same volume.
//
// Acceptance:
//  1. If Replace returns nil, `current` MUST resolve to the new target.
//  2. If Replace returns an error, `current` MUST still resolve to the
//     old target (proved by inducing a failure via a nonexistent
//     targetDir — Create() fails first, we never touch the existing
//     junction, so it must still point at v1).
//  3. There is no code path that both unlinks the old junction and
//     fails to install the new one — a code inspection guarantee that
//     this test locks in by exercising both success and failure paths.
func TestReplace_AtomicNeverLeavesGoneState(t *testing.T) {
	root := t.TempDir()
	v1 := filepath.Join(root, "app", "1.0.0")
	v2 := filepath.Join(root, "app", "1.1.0")
	link := filepath.Join(root, "current")
	for _, d := range []string{v1, v2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(v1, "marker.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v2, "marker.txt"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Initial state: current -> v1.
	if err := Create(link, v1); err != nil {
		t.Fatalf("Create v1: %v", err)
	}

	// -- Success path: Replace returns nil => current points at v2.
	if err := Replace(link, v2); err != nil {
		t.Fatalf("Replace(v2): %v", err)
	}
	got, err := os.ReadFile(filepath.Join(link, "marker.txt"))
	if err != nil {
		t.Fatalf("read via current after Replace: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("after successful Replace, current should resolve to v2, got %q", got)
	}
	// No .new staging leftover after a successful swap.
	if _, err := os.Lstat(link + ".new"); !os.IsNotExist(err) {
		t.Fatalf("stray %s.new after successful Replace: err=%v", link, err)
	}

	// -- Failure path: point at a nonexistent target. Create() fails
	// before we touch the existing junction, so current MUST still
	// resolve to v2 (its current target). The critical invariant is:
	// current is NEVER "gone" — it resolves to either the old or new
	// target on every observable moment.
	nonexistent := filepath.Join(root, "app", "9.9.9-does-not-exist")
	if err := Replace(link, nonexistent); err == nil {
		t.Fatal("Replace with nonexistent target should have failed")
	}
	got, err = os.ReadFile(filepath.Join(link, "marker.txt"))
	if err != nil {
		t.Fatalf("current gone after failed Replace: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("after failed Replace, current should still resolve to v2, got %q", got)
	}
	// And no orphan .new junction either.
	if _, err := os.Lstat(link + ".new"); !os.IsNotExist(err) {
		t.Fatalf("stray %s.new after failed Replace: err=%v", link, err)
	}
}

// TestReplace_CleansStaleStagedJunction ensures a leftover `<link>.new`
// from a prior aborted swap does not block a subsequent Replace call.
func TestReplace_CleansStaleStagedJunction(t *testing.T) {
	root := t.TempDir()
	v1 := filepath.Join(root, "v1")
	v2 := filepath.Join(root, "v2")
	link := filepath.Join(root, "current")
	for _, d := range []string{v1, v2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(v2, "which.txt"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Create(link, v1); err != nil {
		t.Fatal(err)
	}
	// Simulate a prior aborted swap: `<link>.new` already exists pointing
	// somewhere. Replace must not choke on it.
	if err := Create(link+".new", v1); err != nil {
		t.Fatal(err)
	}
	if err := Replace(link, v2); err != nil {
		t.Fatalf("Replace with stale .new leftover: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(link, "which.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Fatalf("expected v2 after Replace, got %q", got)
	}
}

func equalIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ai, bi := a[i], b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai += 32
		}
		if bi >= 'A' && bi <= 'Z' {
			bi += 32
		}
		if ai != bi {
			return false
		}
	}
	return true
}
