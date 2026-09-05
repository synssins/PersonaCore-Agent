// Package prune retains the newest N version directories in <install>\app\
// and deletes the rest.
package prune

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/synssins/PersonaCore-Agent/updater/internal/manifest"
)

// KeepNewest removes all subdirectories of appDir whose names parse as
// valid semver, keeping the newest `keep` and any additional entries
// listed in `always` (typically: the version we just installed and the
// version currently pointed to by `current`).
//
// Returns the list of directory names actually deleted.
func KeepNewest(appDir string, keep int, always []string) ([]string, error) {
	if keep < 1 {
		keep = 1
	}
	entries, err := os.ReadDir(appDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("prune: read %s: %w", appDir, err)
	}

	type verEntry struct {
		name     string
		maj, min, pat int
	}
	var versions []verEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		maj, min, pat, err := manifest.ParseVersion(e.Name())
		if err != nil {
			continue // not a version dir; leave alone
		}
		versions = append(versions, verEntry{e.Name(), maj, min, pat})
	}

	sort.Slice(versions, func(i, j int) bool {
		if versions[i].maj != versions[j].maj {
			return versions[i].maj > versions[j].maj
		}
		if versions[i].min != versions[j].min {
			return versions[i].min > versions[j].min
		}
		return versions[i].pat > versions[j].pat
	})

	protect := make(map[string]bool)
	for i, v := range versions {
		if i < keep {
			protect[v.name] = true
		}
	}
	for _, a := range always {
		protect[a] = true
	}

	var deleted []string
	for _, v := range versions {
		if protect[v.name] {
			continue
		}
		full := filepath.Join(appDir, v.name)
		if err := os.RemoveAll(full); err != nil {
			return deleted, fmt.Errorf("prune: rm %s: %w", full, err)
		}
		deleted = append(deleted, v.name)
	}
	return deleted, nil
}
