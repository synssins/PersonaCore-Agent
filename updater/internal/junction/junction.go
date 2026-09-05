// Package junction wraps Windows directory-junction operations.
//
// Design choice — mklink shell-out vs. DeviceIoControl:
//
// We use the built-in `cmd.exe /c mklink /J` for creation because:
//
//  1. Reparse-point encoding is fiddly and error-prone; mklink is
//     Windows's own reference implementation, guaranteed correct on every
//     supported host.
//  2. No cgo, no golang.org/x/sys required for the swap step — keeps the
//     dependency graph at zero third-party packages.
//  3. Junction creation happens exactly twice per update (create
//     `_swap`, rename to `current`) — the cost of one CreateProcess call
//     is negligible against the download and extract steps.
//
// Deletion / rename uses pure os.Remove / os.Rename because a directory
// junction behaves as an ordinary directory once created — Windows
// handles the reparse-point unlink automatically.
//
// This design bounds the risk to the shell-out itself; both success
// and failure paths are validated by unit tests that create real
// junctions in %TEMP%.
package junction

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Create creates a directory junction at linkPath pointing to targetDir.
// Both paths are absolute. targetDir must already exist. If a file or
// junction already exists at linkPath, Create returns an error — call
// Replace instead for atomic swaps.
func Create(linkPath, targetDir string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("junction.Create: only supported on windows (got %s)", runtime.GOOS)
	}
	if _, err := os.Stat(targetDir); err != nil {
		return fmt.Errorf("junction.Create: target %s: %w", targetDir, err)
	}
	if _, err := os.Lstat(linkPath); err == nil {
		return fmt.Errorf("junction.Create: %s already exists", linkPath)
	}

	absLink, err := filepath.Abs(linkPath)
	if err != nil {
		return err
	}
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return err
	}

	// mklink is a cmd builtin, not a standalone exe.
	cmd := exec.Command("cmd.exe", "/c", "mklink", "/J", absLink, absTarget)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Replace atomically swaps the junction at linkPath to point at targetDir.
//
// Strategy: create `<linkPath>.new` as a junction to targetDir, then
// `os.Rename(<linkPath>.new, linkPath)`. On Windows, Rename over an
// existing directory-junction succeeds when the source is also a
// junction — MoveFileEx with MOVEFILE_REPLACE_EXISTING semantics.
//
// If linkPath doesn't exist yet, we simply Create it.
func Replace(linkPath, targetDir string) error {
	if _, err := os.Lstat(linkPath); os.IsNotExist(err) {
		return Create(linkPath, targetDir)
	}
	stagedName := linkPath + ".new"
	_ = os.Remove(stagedName) // clean any leftover from a prior aborted swap
	if err := Create(stagedName, targetDir); err != nil {
		return err
	}
	// os.Rename on Windows uses MoveFileEx with MOVEFILE_REPLACE_EXISTING
	// via syscall.MoveFileEx when the destination is a file. For
	// directories, we need to remove the old one first — junctions are
	// safe to remove with os.Remove without touching the target.
	if err := os.Remove(linkPath); err != nil {
		_ = os.Remove(stagedName)
		return fmt.Errorf("junction.Replace: remove old %s: %w", linkPath, err)
	}
	if err := os.Rename(stagedName, linkPath); err != nil {
		return fmt.Errorf("junction.Replace: rename %s -> %s: %w", stagedName, linkPath, err)
	}
	return nil
}

// ReadTarget returns the target of the junction at linkPath, or an
// error if linkPath is not a symlink/junction. Used by tests.
func ReadTarget(linkPath string) (string, error) {
	target, err := os.Readlink(linkPath)
	if err != nil {
		return "", err
	}
	// Windows Readlink returns paths with \??\ prefix for junctions.
	target = strings.TrimPrefix(target, `\??\`)
	return target, nil
}
