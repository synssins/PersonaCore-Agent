package main

import (
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
