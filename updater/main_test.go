package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun_UsageWhenNoArgs(t *testing.T) {
	if code := run([]string{}); code != 2 {
		t.Fatalf("expected exit 2 for missing subcommand, got %d", code)
	}
}

func TestRun_CheckRequiresURLs(t *testing.T) {
	// Provide a pubkey so we reach the URL check.
	if code := run([]string{"--check", "--pubkey-hex", "00"}); code == 0 {
		t.Fatal("expected non-zero for --check without URLs")
	}
}

func TestRun_UpdateWithoutPending(t *testing.T) {
	// No PC_AGENT_APPDATA + no --pending -> immediate failure path.
	t.Setenv("PC_AGENT_APPDATA", t.TempDir()) // empty dir, no pending file
	code := run([]string{"--update", "--logs-dir", t.TempDir()})
	if code == 0 {
		t.Fatal("expected non-zero when pending_update.json is missing")
	}
}

// TestRun_RollbackFlagParsed verifies that `--rollback <ver>` is
// recognised and reaches the rollback code path (as opposed to falling
// through to the usage branch or being confused with --update). We
// point --install-root at an empty tempdir so the code fails early
// with a "target version not installed" error — the SIGNAL we're after
// is that we got that specific failure, which proves the flag was
// parsed AND cmdRollback was dispatched (not the usage branch).
func TestRun_RollbackFlagParsed(t *testing.T) {
	install := t.TempDir()
	logs := t.TempDir()
	// Set the sentinel so RelayIfNeeded takes the pass-through branch;
	// otherwise it would try to copy the test binary to %TEMP% and
	// spawn a child that would print usage help.
	t.Setenv("PC_AGENT_UPDATER_SELF_RELAY", "1")
	code := run([]string{
		"--rollback", "0.0.1",
		"--install-root", install,
		"--logs-dir", logs,
	})
	// Should be non-zero because we haven't staged app/0.0.1/.
	if code == 0 {
		t.Fatal("expected non-zero when target version dir is absent")
	}
	// And the log must show we entered the rollback path, not the
	// usage branch — inspect the log file for a rollback-specific
	// message.
	entries, err := os.ReadDir(logs)
	if err != nil {
		t.Fatal(err)
	}
	var log string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".log" {
			b, err := os.ReadFile(filepath.Join(logs, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			log = string(b)
			break
		}
	}
	if log == "" {
		t.Fatal("expected a rollback log file, got none")
	}
	if !containsAny(log, []string{"rollback", "target version"}) {
		t.Fatalf("log doesn't look like a rollback failure:\n%s", log)
	}
}

// TestRun_RollbackAndUpdateAreExclusive: if both flags are given, the
// switch statement in run() dispatches to --check first, then
// --rollback (before --update). Verify --rollback wins over --update.
func TestRun_RollbackAndUpdateAreExclusive(t *testing.T) {
	install := t.TempDir()
	logs := t.TempDir()
	t.Setenv("PC_AGENT_UPDATER_SELF_RELAY", "1")
	// Both flags set — the code must pick rollback (per the switch
	// order in run()). We assert the log contains the rollback
	// message, not update-flow messages.
	code := run([]string{
		"--rollback", "1.0.0",
		"--update",
		"--install-root", install,
		"--logs-dir", logs,
	})
	if code == 0 {
		t.Fatal("expected non-zero (target dir missing)")
	}
	entries, _ := os.ReadDir(logs)
	var log string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".log" {
			b, _ := os.ReadFile(filepath.Join(logs, e.Name()))
			log = string(b)
		}
	}
	if log == "" || !containsAny(log, []string{"rollback"}) {
		t.Fatalf("expected rollback to win over --update; log:\n%s", log)
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
