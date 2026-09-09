package swap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/synssins/PersonaCore-Agent/updater/internal/origin"
)

func strictPolicy(t *testing.T) *origin.Policy {
	t.Helper()
	pol, err := origin.New(origin.DefaultRepo, nil)
	if err != nil {
		t.Fatalf("origin.New: %v", err)
	}
	return pol
}

func TestDownload_RequiresPolicy(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "x.bin")
	_, err := Download(nil, nil,
		"https://github.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip", dest, "")
	if err == nil {
		t.Fatal("expected refusal when no update-source policy is supplied")
	}
	if !strings.Contains(err.Error(), "policy") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestDownload_RefusesOffOriginURLs(t *testing.T) {
	pol := strictPolicy(t)
	cases := map[string]string{
		"foreign host":  "https://evil.example.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"plain http":    "http://github.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"other repo":    "https://github.com/attacker/evil/releases/download/v1/a.zip",
		"not a release": "https://github.com/synssins/PersonaCore-Agent/raw/main/a.zip",
		"loopback":      "http://127.0.0.1:8080/a.zip",
		"credentials":   "https://github.com@evil.example.com/a.zip",
		"odd port":      "https://github.com:8443/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
	}
	for name, rawURL := range cases {
		dest := filepath.Join(t.TempDir(), "x.bin")
		derr := func() error {
			_, e := Download(nil, pol, rawURL, dest, "")
			return e
		}()
		if derr == nil {
			t.Fatalf("%s: expected refusal for %s", name, rawURL)
		}
		if !strings.Contains(derr.Error(), "refused") {
			t.Fatalf("%s: expected a stated reason, got %v", name, derr)
		}
		if _, serr := os.Stat(dest); !os.IsNotExist(serr) {
			t.Fatalf("%s: a refused download must not create %s", name, dest)
		}
	}
}

// fakeGitHub stands in for GitHub's release hosting: one TLS server answering
// for several virtual hosts, plus a client whose dialer sends every hostname
// to it. The redirect policy runs before the dial, so this exercises the real
// chain — github.com 302s to the user-content CDN, which serves the bytes.
func fakeGitHub(t *testing.T, payload []byte) *http.Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch {
		case host == "github.com" && strings.HasSuffix(r.URL.Path, "/agent.zip"):
			http.Redirect(w, r,
				"https://objects.githubusercontent.com/blob/agent.zip", http.StatusFound)
		case host == "github.com" && strings.HasSuffix(r.URL.Path, "/legacy.zip"):
			http.Redirect(w, r,
				"https://github-releases.githubusercontent.com/blob/agent.zip", http.StatusFound)
		case host == "github.com" && strings.HasSuffix(r.URL.Path, "/evil.zip"):
			http.Redirect(w, r, "https://evil.example.com/payload", http.StatusFound)
		case host == "github.com" && strings.HasSuffix(r.URL.Path, "/downgrade.zip"):
			http.Redirect(w, r,
				"http://objects.githubusercontent.com/blob/agent.zip", http.StatusFound)
		case host == "github.com" && strings.HasSuffix(r.URL.Path, "/lookalike.zip"):
			// A host that merely *contains* the CDN name.
			http.Redirect(w, r,
				"https://objects.githubusercontent.com.evil.example/x", http.StatusFound)
		case host == "objects.githubusercontent.com",
			host == "github-releases.githubusercontent.com":
			_, _ = w.Write(payload)
		default:
			_, _ = w.Write([]byte("PWNED"))
		}
	}))
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// Hostname verification is beside the point here; what is being
			// tested is which hostnames the policy lets us reach at all.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}
}

func TestDownload_FollowsGitHubAssetRedirect(t *testing.T) {
	payload := []byte("the real agent zip")
	sum := sha256.Sum256(payload)
	pol := strictPolicy(t)
	client := fakeGitHub(t, payload)

	for name, asset := range map[string]string{
		"current CDN host": "agent.zip",
		"legacy CDN host":  "legacy.zip",
	} {
		dest := filepath.Join(t.TempDir(), "agent.zip")
		n, err := Download(client, pol,
			"https://github.com/synssins/PersonaCore-Agent/releases/download/v0.2.0/"+asset,
			dest, hex.EncodeToString(sum[:]))
		if err != nil {
			t.Fatalf("%s: a legitimate github.com release URL must download "+
				"through the CDN redirect: %v", name, err)
		}
		if n != int64(len(payload)) {
			t.Fatalf("%s: bytes %d want %d", name, n, len(payload))
		}
		got, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s: content mismatch", name)
		}
	}
}

func TestDownload_RefusesHostileRedirect(t *testing.T) {
	pol := strictPolicy(t)
	client := fakeGitHub(t, []byte("the real agent zip"))

	for name, asset := range map[string]string{
		"off-allowlist host": "evil.zip",
		"scheme downgrade":   "downgrade.zip",
		"suffix lookalike":   "lookalike.zip",
	} {
		dest := filepath.Join(t.TempDir(), "agent.zip")
		_, derr := Download(client, pol,
			"https://github.com/synssins/PersonaCore-Agent/releases/download/v0.2.0/"+asset,
			dest, "")
		if derr == nil {
			t.Fatalf("%s: a redirect off the pinned origin must fail", name)
		}
		if !strings.Contains(derr.Error(), "origin:") {
			t.Fatalf("%s: expected an origin-policy reason, got %v", name, derr)
		}
		if _, serr := os.Stat(dest); !os.IsNotExist(serr) {
			t.Fatalf("%s: nothing must be written", name)
		}
	}
}

// A caller that hands Download an un-hardened client still gets the pin: the
// policy is copied onto the client Download actually uses.
func TestDownload_HardensCallerSuppliedClient(t *testing.T) {
	pol := strictPolicy(t)
	client := fakeGitHub(t, []byte("x"))
	client.CheckRedirect = nil

	dest := filepath.Join(t.TempDir(), "agent.zip")
	_, derr := Download(client, pol,
		"https://github.com/synssins/PersonaCore-Agent/releases/download/v0.2.0/evil.zip",
		dest, "")
	if derr == nil {
		t.Fatal("expected the hostile redirect to be refused despite a bare client")
	}
	if client.CheckRedirect != nil {
		t.Fatal("Download must not mutate the caller's client")
	}
}
