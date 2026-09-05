// Package swap implements the mechanical bits of an update transaction:
// wait for the agent to exit, download+verify the new artifact, extract
// it, atomically swap the `current` junction, and relaunch.
//
// All I/O errors are returned wrapped; nothing panics. The caller
// (main.go) is responsible for logging + rollback bookkeeping.
package swap

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/synssins/PersonaCore-Agent/updater/internal/junction"
)

// InstallLayout describes the directory layout the updater operates on.
//
//	Root/
//	  app/
//	    <version>/    <-- one dir per installed version
//	  current  ->  app/<version>   (directory junction)
//	  _incoming/     <-- staging area, always empty between updates
type InstallLayout struct {
	Root string
}

// AppDir returns Root/app.
func (l InstallLayout) AppDir() string { return filepath.Join(l.Root, "app") }

// CurrentJunction returns Root/current.
func (l InstallLayout) CurrentJunction() string { return filepath.Join(l.Root, "current") }

// IncomingDir returns Root/_incoming.
func (l InstallLayout) IncomingDir() string { return filepath.Join(l.Root, "_incoming") }

// VersionDir returns Root/app/<version>.
func (l InstallLayout) VersionDir(v string) string { return filepath.Join(l.AppDir(), v) }

// WaitForPidExit polls until the given PID no longer exists, or the
// grace period expires. On expiry, it attempts a hard kill via
// TerminateProcess (Windows) or SIGKILL. Returns nil if the process is
// gone (either naturally or forced).
func WaitForPidExit(pid int, grace time.Duration) error {
	if pid <= 0 {
		return nil
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	// Hard kill.
	if runtime.GOOS == "windows" {
		out, err := exec.Command("taskkill", "/PID", fmt.Sprint(pid), "/F").CombinedOutput()
		if err != nil {
			// If taskkill reports "process not found", treat as success.
			if strings.Contains(strings.ToLower(string(out)), "not found") ||
				strings.Contains(strings.ToLower(string(out)), "no running") {
				return nil
			}
			return fmt.Errorf("taskkill %d: %w: %s", pid, err, strings.TrimSpace(string(out)))
		}
	} else {
		proc, err := os.FindProcess(pid)
		if err == nil {
			_ = proc.Kill()
		}
	}
	// Give the OS a moment to reap.
	time.Sleep(200 * time.Millisecond)
	if pidAlive(pid) {
		return fmt.Errorf("pid %d still alive after force kill", pid)
	}
	return nil
}

func pidAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		// On Windows FindProcess always succeeds; probe with a signal 0
		// equivalent via OpenProcess. Simplest cross-version: run
		// tasklist filtered by PID.
		out, err := exec.Command("tasklist", "/FI", "PID eq "+fmt.Sprint(pid), "/NH").Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), fmt.Sprint(pid))
	}
	// Unix: signal 0 checks existence.
	return proc.Signal(nil) == nil
}

// Download fetches url into destPath, verifying its SHA-256 against
// wantSHA256Hex as it streams. Overwrites destPath if it exists.
// Returns the actual size in bytes.
func Download(client *http.Client, url, destPath, wantSHA256Hex string) (int64, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return 0, err
	}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	tmp := destPath + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	if closeErr := f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("download stream: %w", err)
	}
	gotHex := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(gotHex, wantSHA256Hex) {
		os.Remove(tmp)
		return 0, fmt.Errorf("sha256 mismatch: want %s got %s", wantSHA256Hex, gotHex)
	}
	_ = os.Remove(destPath)
	if err := os.Rename(tmp, destPath); err != nil {
		return 0, err
	}
	return n, nil
}

// ExtractZip unpacks zipPath into destDir. destDir is created if
// absent; existing files are OVERWRITTEN. Rejects any zip entry whose
// canonicalised path escapes destDir (zip-slip guard).
func ExtractZip(zipPath, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip %s: %w", zipPath, err)
	}
	defer r.Close()
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	for _, f := range r.File {
		clean := filepath.Clean(f.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("zip-slip: refusing %q", f.Name)
		}
		target := filepath.Join(absDest, clean)
		if !strings.HasPrefix(target, absDest+string(os.PathSeparator)) && target != absDest {
			return fmt.Errorf("zip-slip: %q escapes %s", f.Name, absDest)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		in, err := f.Open()
		if err != nil {
			out.Close()
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			out.Close()
			return err
		}
		in.Close()
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}

// SwapTo points layout.CurrentJunction() at layout.VersionDir(newVersion).
// Returns the version the junction USED to point at (empty if none) so
// the caller can roll back on relaunch failure.
func SwapTo(layout InstallLayout, newVersion string) (previousVersion string, err error) {
	target := layout.VersionDir(newVersion)
	if _, err := os.Stat(target); err != nil {
		return "", fmt.Errorf("swap: target %s missing: %w", target, err)
	}
	// Capture the old target before swap.
	if oldTarget, rerr := junction.ReadTarget(layout.CurrentJunction()); rerr == nil {
		previousVersion = filepath.Base(oldTarget)
	}
	if err := junction.Replace(layout.CurrentJunction(), target); err != nil {
		return previousVersion, err
	}
	return previousVersion, nil
}

// Relaunch spawns <install>\current\Agent.exe with the given args as a
// detached process and returns its PID. The updater exits shortly after.
func Relaunch(layout InstallLayout, args []string) (int, error) {
	agent := filepath.Join(layout.CurrentJunction(), "Agent.exe")
	if _, err := os.Stat(agent); err != nil {
		return 0, fmt.Errorf("relaunch: %s: %w", agent, err)
	}
	cmd := exec.Command(agent, args...)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	// Release the handle so the child fully detaches.
	go func() { _ = cmd.Wait() }()
	if cmd.Process == nil {
		return 0, errors.New("relaunch: process handle nil after Start")
	}
	return cmd.Process.Pid, nil
}

// EnsureIncoming clears (or creates) layout.IncomingDir() so a partially
// interrupted prior run doesn't leak into this one.
func EnsureIncoming(layout InstallLayout) (string, error) {
	dir := layout.IncomingDir()
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
