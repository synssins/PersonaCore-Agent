package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readLog(t *testing.T, logsDir string) string {
	t.Helper()
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".log" {
			b, rerr := os.ReadFile(filepath.Join(logsDir, e.Name()))
			if rerr != nil {
				t.Fatal(rerr)
			}
			return string(b)
		}
	}
	return ""
}

// The baked-in default must be this project's repo. A build that forgot the
// ldflag still has to be pinned, not open.
func TestBakedPinDefaultsToProjectRepo(t *testing.T) {
	if Repo != "synssins/PersonaCore-Agent" {
		t.Fatalf("default repo pin = %q, want the project repo", Repo)
	}
	if ExtraOrigins != "" {
		t.Fatalf("a build with no -X main.ExtraOrigins must have none, got %q", ExtraOrigins)
	}
	pol, err := originPolicy()
	if err != nil {
		t.Fatalf("originPolicy: %v", err)
	}
	if err := pol.CheckArtifactURL("http://127.0.0.1:1/agent.zip"); err == nil {
		t.Fatal("a default build must not reach a local host")
	}
}

func writePending(t *testing.T, dir, agentURL, updaterURL string) {
	t.Helper()
	payload := map[string]any{
		"schema_version": 1,
		"verified":       true,
		"agent_pid":      0,
		"manifest": map[string]any{
			"version":     "0.0.2",
			"channel":     "stable",
			"released_at": "2026-01-01T00:00:00Z",
			"mandatory":   false,
			"notes_url":   "https://example.invalid/n",
			"artifacts": map[string]any{
				"agent":   map[string]any{"url": agentURL, "sha256": strings.Repeat("a", 64), "size": 1},
				"updater": map[string]any{"url": updaterURL, "sha256": strings.Repeat("b", 64), "size": 1},
			},
			"min_updater_version": "0.0.1",
		},
		"manifest_b64":  base64.StdEncoding.EncodeToString([]byte("{}")),
		"signature_b64": base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pending_update.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A staged manifest naming a foreign download host is refused up front —
// before the self-relay, before any signature work, and certainly before any
// bytes are fetched.
func TestRun_UpdateRefusesOffOriginArtifact(t *testing.T) {
	appdata := t.TempDir()
	logs := t.TempDir()
	writePending(t, appdata,
		"https://evil.example.com/agent.zip",
		"https://github.com/synssins/PersonaCore-Agent/releases/download/v0.0.2/Updater.exe")
	t.Setenv("PC_AGENT_APPDATA", appdata)
	t.Setenv("PC_AGENT_UPDATER_SELF_RELAY", "1")

	code := run([]string{"--update", "--logs-dir", logs, "--pubkey-hex", strings.Repeat("11", 32)})
	if code == 0 {
		t.Fatal("expected non-zero for an off-origin artifact URL")
	}
	log := readLog(t, logs)
	if !strings.Contains(log, "agent artifact rejected") {
		t.Fatalf("expected a stated reason in the log, got:\n%s", log)
	}
	if !strings.Contains(log, "pinned update source") {
		t.Fatalf("expected the origin-policy reason, got:\n%s", log)
	}
}

func TestRun_UpdateRefusesHTTPArtifact(t *testing.T) {
	appdata := t.TempDir()
	logs := t.TempDir()
	writePending(t, appdata,
		"http://github.com/synssins/PersonaCore-Agent/releases/download/v0.0.2/agent.zip",
		"https://github.com/synssins/PersonaCore-Agent/releases/download/v0.0.2/Updater.exe")
	t.Setenv("PC_AGENT_APPDATA", appdata)
	t.Setenv("PC_AGENT_UPDATER_SELF_RELAY", "1")

	code := run([]string{"--update", "--logs-dir", logs, "--pubkey-hex", strings.Repeat("11", 32)})
	if code == 0 {
		t.Fatal("expected non-zero for an http:// artifact URL")
	}
	if log := readLog(t, logs); !strings.Contains(log, "must use https") {
		t.Fatalf("expected an https-only reason in the log, got:\n%s", log)
	}
}

// The updater artifact is pinned too, even though --update only downloads the
// agent zip today.
func TestRun_UpdateRefusesOffOriginUpdaterArtifact(t *testing.T) {
	appdata := t.TempDir()
	logs := t.TempDir()
	writePending(t, appdata,
		"https://github.com/synssins/PersonaCore-Agent/releases/download/v0.0.2/agent.zip",
		"https://evil.example.com/Updater.exe")
	t.Setenv("PC_AGENT_APPDATA", appdata)
	t.Setenv("PC_AGENT_UPDATER_SELF_RELAY", "1")

	if code := run([]string{"--update", "--logs-dir", logs,
		"--pubkey-hex", strings.Repeat("11", 32)}); code == 0 {
		t.Fatal("expected non-zero for an off-origin updater URL")
	}
	if log := readLog(t, logs); !strings.Contains(log, "updater artifact rejected") {
		t.Fatalf("expected a stated reason in the log, got:\n%s", log)
	}
}

func TestRun_CheckRefusesOffOriginURLs(t *testing.T) {
	logs := t.TempDir()
	code := run([]string{
		"--check",
		"--pubkey-hex", strings.Repeat("11", 32),
		"--check-manifest", "https://evil.example.com/manifest.json",
		"--check-sig", "https://evil.example.com/manifest.json.sig",
		"--logs-dir", logs,
	})
	if code == 0 {
		t.Fatal("expected non-zero for an off-origin --check URL")
	}
	if log := readLog(t, logs); !strings.Contains(log, "pinned update source") {
		t.Fatalf("expected the origin-policy reason, got:\n%s", log)
	}
}
