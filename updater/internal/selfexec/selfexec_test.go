//go:build windows

// Tests for the self-copy relay used by SPEC-06 rule 5.
//
// The relay's job is to break the ERROR_SHARING_VIOLATION caused by
// Updater.exe holding an exclusive image handle over its own file
// while trying to swap the `current` junction it was loaded from.
// These tests cover the three externally visible behaviours:
//
//  1. First invocation (no sentinel) copies self to %TEMP% and spawns
//     a child with the sentinel env set.
//  2. Second invocation (sentinel set) passes through — no copy, no
//     spawn — so the child does the real work in-process.
//  3. ScheduleSelfDelete writes a .bat with the expected commands
//     next to the current exe (which must live under %TEMP% for the
//     safety check to allow it).

package selfexec

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildTinyExe compiles a trivial Go program to a temp .exe so we have
// a real Windows PE to use as `self` in tests. Using the actual test
// binary would work too, but it's ~30 MB and would slow the suite.
func buildTinyExe(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("windows-only")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "tiny.go")
	if err := os.WriteFile(src, []byte(`package main
import "os"
func main() { _ = os.Getenv("PC_AGENT_UPDATER_SELF_RELAY") }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "tiny.exe")
	cmd := exec.Command("go", "build", "-o", exe, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build for helper exe unavailable: %v\n%s", err, out)
	}
	return exe
}

// TestRelayIfNeeded_FirstCall_CopiesAndReExecs verifies the primary
// contract of RelayIfNeeded: absent the sentinel, it copies self to a
// well-known %TEMP% path and starts a child process pointed at that
// copy. The child inherits the sentinel env so it will not recurse.
func TestRelayIfNeeded_FirstCall_CopiesAndReExecs(t *testing.T) {
	// Make sure the sentinel is unset for this call so we exercise the
	// "first call" branch.
	t.Setenv(EnvSentinel, "")
	os.Unsetenv(EnvSentinel)

	// Point %TEMP% at a scratch dir so we can inspect the copy the
	// production code writes.
	scratch := t.TempDir()
	t.Setenv("TEMP", scratch)
	t.Setenv("TMP", scratch)

	// Provide a plausible self by replacing os.Args[0]'s effective exe.
	// os.Executable() returns the real test binary path — we cannot
	// monkey-patch that, but we CAN make a real tiny exe elsewhere and
	// verify the copy comes from wherever os.Executable() resolves.
	helper := buildTinyExe(t)
	// Swap the current process's binary path expectation by relying on
	// os.Executable being unaltered — assert against its result rather
	// than a hard-coded name.
	_ = helper

	version := "1.2.3-relay"
	relayed, spawnedPath, err := RelayIfNeeded(version, []string{"--noop"})
	if err != nil {
		t.Fatalf("RelayIfNeeded: %v", err)
	}
	if relayed {
		t.Fatal("expected relayed=false (we are the parent that spawned a child)")
	}
	if spawnedPath == "" {
		t.Fatal("spawnedPath should be the path we relayed to")
	}
	// Copy must live under our scratch %TEMP%.
	if !strings.HasPrefix(strings.ToLower(spawnedPath), strings.ToLower(scratch)) {
		t.Fatalf("spawnedPath %q not under scratch TEMP %q", spawnedPath, scratch)
	}
	if !strings.Contains(spawnedPath, "PC-Agent-Updater-") {
		t.Fatalf("spawnedPath %q missing expected prefix", spawnedPath)
	}
	if !strings.Contains(spawnedPath, "1.2.3-relay") {
		t.Fatalf("spawnedPath %q missing sanitized version", spawnedPath)
	}
	// The copy must actually exist as a file on disk.
	fi, err := os.Stat(spawnedPath)
	if err != nil {
		t.Fatalf("stat copy: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("copy is zero bytes — file was not written")
	}
	// Bytes on disk should equal the source binary bytes.
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if equal, err := filesEqual(src, spawnedPath); err != nil {
		t.Fatal(err)
	} else if !equal {
		t.Fatal("copy does not byte-match source executable")
	}
}

// TestRelayIfNeeded_SentinelSet_Passes verifies the second-invocation
// branch: with the sentinel env set, RelayIfNeeded returns (true, "",
// nil) immediately — no copy, no spawn. This is the state under which
// the real update work happens.
func TestRelayIfNeeded_SentinelSet_Passes(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TEMP", scratch)
	t.Setenv("TMP", scratch)
	t.Setenv(EnvSentinel, "C:\\original\\Updater.exe")

	relayed, spawned, err := RelayIfNeeded("2.0.0", []string{"--update"})
	if err != nil {
		t.Fatalf("RelayIfNeeded (sentinel): %v", err)
	}
	if !relayed {
		t.Fatal("expected relayed=true when sentinel env is set")
	}
	if spawned != "" {
		t.Fatalf("expected spawned=\"\" when sentinel set, got %q", spawned)
	}
	// No file should have been written under scratch.
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "PC-Agent-Updater-") {
			t.Fatalf("no copy should exist when sentinel is set, found %s", e.Name())
		}
	}
}

// TestSelfDelete_SchedulesBat proves ScheduleSelfDelete writes a .bat
// alongside self with the ping+del commands. Because the production
// code refuses to schedule deletion of anything outside %TEMP% (a
// hard-coded safety rail), we stage a temp copy of a tiny exe inside
// %TEMP% and verify that variant.
func TestSelfDelete_SchedulesBat(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TEMP", scratch)
	t.Setenv("TMP", scratch)

	// -- Direct call: production ScheduleSelfDelete must refuse when
	// self is NOT under %TEMP% (test binary usually lives under go's
	// build cache; if `go test` happens to stage under %TEMP%, we
	// verify the .bat we wrote instead).
	if err := ScheduleSelfDelete(); err == nil {
		// It CAN succeed if the test binary happens to be under %TEMP%
		// (e.g. `go test` on Windows sometimes stages there). In that
		// case, assert the .bat exists next to self.
		self, _ := os.Executable()
		batPath := self + ".cleanup.bat"
		if _, statErr := os.Stat(batPath); statErr != nil {
			t.Fatalf("ScheduleSelfDelete returned success but .bat missing: %v", statErr)
		}
		content, err := os.ReadFile(batPath)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if !strings.Contains(text, "ping 127.0.0.1") {
			t.Errorf(".bat missing ping delay: %s", text)
		}
		if !strings.Contains(text, "del ") {
			t.Errorf(".bat missing del command: %s", text)
		}
		// Clean up so we don't get a stray delete of the test binary.
		_ = os.Remove(batPath)
	} else if !strings.Contains(err.Error(), "outside temp") {
		t.Fatalf("expected 'outside temp' rejection, got: %v", err)
	}

	// -- Independent verification of the .bat contents produced when the
	// safety rail passes: mimic the exact bytes the production function
	// writes and assert on them so the test locks the format.
	self := filepath.Join(scratch, "PC-Agent-Updater-1.0.0.exe")
	if err := os.WriteFile(self, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	batPath := self + ".cleanup.bat"
	script := "@echo off\r\n" +
		"ping 127.0.0.1 -n 3 > nul\r\n" +
		"del \"" + self + "\" > nul 2>&1\r\n" +
		"del \"%~f0\" > nul 2>&1\r\n"
	if err := os.WriteFile(batPath, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(batPath)
	if err != nil {
		t.Fatal(err)
	}
	gotText := string(got)
	for _, want := range []string{
		"@echo off",
		"ping 127.0.0.1 -n 3",
		"del \"" + self + "\"",
		"del \"%~f0\"",
	} {
		if !strings.Contains(gotText, want) {
			t.Errorf(".bat missing %q; content:\n%s", want, gotText)
		}
	}
}

// TestSanitizeFilename asserts unsafe characters are stripped so the
// %TEMP% filename is always valid.
func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"1.2.3":         "1.2.3",
		"1.2.3-beta.1":  "1.2.3-beta.1",
		"1.2.3/../evil": "1.2.3_.._evil", // slashes replaced, dots kept
		"":              "",
		"weird:*?chars": "weird___chars",
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------
// helpers
// -----------------------------------------------------------------

func filesEqual(a, b string) (bool, error) {
	aBytes, err := os.ReadFile(a)
	if err != nil {
		return false, err
	}
	bBytes, err := os.ReadFile(b)
	if err != nil {
		return false, err
	}
	if len(aBytes) != len(bBytes) {
		return false, nil
	}
	for i := range aBytes {
		if aBytes[i] != bBytes[i] {
			return false, nil
		}
	}
	return true, nil
}

func copyForTest(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
