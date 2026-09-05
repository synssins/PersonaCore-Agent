package prune

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestKeepNewest_KeepsThreeAndAlwaysList(t *testing.T) {
	root := t.TempDir()
	versions := []string{"1.0.0", "1.0.1", "1.1.0", "1.2.0", "1.2.10", "not-a-version"}
	for _, v := range versions {
		if err := os.MkdirAll(filepath.Join(root, v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := KeepNewest(root, 3, []string{"1.0.0"})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	sort.Strings(deleted)
	// Expected: 1.2.10, 1.2.0, 1.1.0 are top-3; 1.0.0 protected via always.
	// 1.0.1 is the loser.
	if len(deleted) != 1 || deleted[0] != "1.0.1" {
		t.Fatalf("unexpected deleted set: %v", deleted)
	}
	// Non-version directories left alone.
	if _, err := os.Stat(filepath.Join(root, "not-a-version")); err != nil {
		t.Fatalf("non-version dir wrongly removed: %v", err)
	}
}

func TestKeepNewest_EmptyDir(t *testing.T) {
	root := t.TempDir()
	deleted, err := KeepNewest(root, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Fatalf("expected no deletions, got %v", deleted)
	}
}

func TestKeepNewest_MissingDir(t *testing.T) {
	deleted, err := KeepNewest(filepath.Join(t.TempDir(), "does-not-exist"), 3, nil)
	if err != nil {
		t.Fatalf("should tolerate missing dir: %v", err)
	}
	if len(deleted) != 0 {
		t.Fatalf("expected no deletions, got %v", deleted)
	}
}
