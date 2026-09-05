package swap

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownload_VerifiesSHA256(t *testing.T) {
	payload := []byte("hello updater world")
	sum := sha256.Sum256(payload)
	sumHex := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "sub", "dl.bin")
	n, err := Download(nil, srv.URL, dest, sumHex)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("bytes: %d want %d", n, len(payload))
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("content mismatch")
	}

	// Wrong hash -> error, no dest file.
	dest2 := filepath.Join(t.TempDir(), "dl2.bin")
	_, err = Download(nil, srv.URL, dest2, "00"+sumHex[2:])
	if err == nil {
		t.Fatal("expected sha mismatch error")
	}
	if _, statErr := os.Stat(dest2); !os.IsNotExist(statErr) {
		t.Fatalf("dest should not exist on hash mismatch, stat err = %v", statErr)
	}
}

func TestDownload_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	if _, err := Download(nil, srv.URL, filepath.Join(t.TempDir(), "x"), ""); err == nil {
		t.Fatal("expected HTTP error")
	}
}

func TestExtractZip_HappyPath(t *testing.T) {
	src := makeZip(t, map[string][]byte{
		"Agent.exe":              []byte("agent-bytes"),
		"_internal/lib.dll":      []byte("lib"),
		"_internal/sub/other.py": []byte("py"),
	})
	dest := filepath.Join(t.TempDir(), "extracted")
	if err := ExtractZip(src, dest); err != nil {
		t.Fatalf("ExtractZip: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "_internal", "sub", "other.py"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "py" {
		t.Fatalf("content mismatch: %s", got)
	}
}

func TestExtractZip_RejectsSlip(t *testing.T) {
	// Craft a zip containing "../evil.txt".
	zpath := filepath.Join(t.TempDir(), "evil.zip")
	f, err := os.Create(zpath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("boom"))
	_ = zw.Close()
	_ = f.Close()
	if err := ExtractZip(zpath, t.TempDir()); err == nil {
		t.Fatal("expected zip-slip rejection")
	}
}

func makeZip(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnsureIncoming_ClearsExisting(t *testing.T) {
	layout := InstallLayout{Root: t.TempDir()}
	junk := filepath.Join(layout.IncomingDir(), "old.txt")
	if err := os.MkdirAll(layout.IncomingDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(junk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureIncoming(layout); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(junk); !os.IsNotExist(err) {
		t.Fatalf("junk file should have been cleared, err=%v", err)
	}
}

func TestLoadPending_Roundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending_update.json")
	// Emit a document identical in shape to what Python stage_pending writes.
	os.WriteFile(path, []byte(`{
  "agent_pid": 4242,
  "manifest": {
    "artifacts": {
      "agent":   {"sha256":"aa","size":1,"url":"https://a"},
      "updater": {"sha256":"bb","size":2,"url":"https://u"}
    },
    "channel": "stable",
    "mandatory": false,
    "min_updater_version": "1.0.0",
    "notes_url": "https://x",
    "released_at": "2026-09-15T04:00:00Z",
    "version": "1.2.3"
  },
  "manifest_b64": "aGVsbG8=",
  "schema_version": 1,
  "signature_b64": "d29ybGQ=",
  "verified": true
}`), 0o644)
	p, mBytes, sBytes, err := LoadPending(path)
	if err != nil {
		t.Fatalf("LoadPending: %v", err)
	}
	if p.AgentPID != 4242 || p.Manifest.Version != "1.2.3" {
		t.Fatalf("unexpected pending: %+v", p)
	}
	if string(mBytes) != "hello" || string(sBytes) != "world" {
		t.Fatalf("bytes decoded wrong: %q %q", mBytes, sBytes)
	}
}
