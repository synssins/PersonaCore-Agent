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
