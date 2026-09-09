package origin

import (
	"net/http"
	"strings"
	"testing"
)

func mustPolicy(t *testing.T, extra ...string) *Policy {
	t.Helper()
	p, err := New(DefaultRepo, extra)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestNew_RejectsMalformedRepoPins(t *testing.T) {
	for _, bad := range []string{
		"", "noslash", "/name", "owner/", "owner/name/extra",
		"owner/../evil", "owner/na me", "ow%2Fner/name",
		"owner/name?x=1", "https://evil.example.com/owner/name",
		strings.Repeat("a", 101) + "/name",
	} {
		if _, err := New(bad, nil); err == nil {
			t.Fatalf("repo pin %q should have been rejected", bad)
		}
	}
	// "owner/name/extra" must not silently become owner="owner".
	if _, err := New("owner/name/extra", nil); err == nil {
		t.Fatal("multi-segment repo pin should be rejected")
	}
}

func TestNew_AcceptsForkPin(t *testing.T) {
	p, err := New("someone-else/PersonaCore-Agent.fork", nil)
	if err != nil {
		t.Fatalf("a fork must be able to retarget the pin: %v", err)
	}
	if p.Repo() != "someone-else/PersonaCore-Agent.fork" {
		t.Fatalf("Repo() = %q", p.Repo())
	}
	if err := p.CheckArtifactURL(
		"https://github.com/someone-else/PersonaCore-Agent.fork/releases/download/v1/a.zip"); err != nil {
		t.Fatalf("fork's own release should pass: %v", err)
	}
	if err := p.CheckArtifactURL(
		"https://github.com/" + DefaultRepo + "/releases/download/v1/a.zip"); err == nil {
		t.Fatal("a fork pin must not still accept upstream")
	}
}

func TestCheckArtifactURL_Accepts(t *testing.T) {
	p := mustPolicy(t)
	for _, ok := range []string{
		"https://github.com/synssins/PersonaCore-Agent/releases/download/v0.2.0/agent.zip",
		"https://github.com:443/synssins/PersonaCore-Agent/releases/download/v0.2.0/agent.zip",
		"https://GitHub.com/SynSsins/personacore-agent/releases/download/v0.2.0/agent.zip",
		"https://github.com./synssins/PersonaCore-Agent/releases/download/v0.2.0/agent.zip",
		"https://github.com/synssins/PersonaCore-Agent/releases/download/v0.2.0/Updater.exe?x=1",
	} {
		if err := p.CheckArtifactURL(ok); err != nil {
			t.Fatalf("%s should be accepted: %v", ok, err)
		}
	}
}

func TestCheckArtifactURL_Rejects(t *testing.T) {
	p := mustPolicy(t)
	for name, bad := range map[string]string{
		"http":                   "http://github.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"ftp":                    "ftp://github.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"file":                   "file:///C:/evil.zip",
		"relative":               "/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"empty":                  "",
		"foreign host":           "https://evil.example.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"suffix lookalike":       "https://github.com.evil.example/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"prefix lookalike":       "https://notgithub.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"credentials":            "https://github.com@evil.example.com/a.zip",
		"credentials reverse":    "https://evil.example.com@github.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"odd port":               "https://github.com:8443/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"wrong repo":             "https://github.com/attacker/evil/releases/download/v1/a.zip",
		"right owner wrong repo": "https://github.com/synssins/other/releases/download/v1/a.zip",
		"not a release":          "https://github.com/synssins/PersonaCore-Agent/raw/main/a.zip",
		"short path":             "https://github.com/synssins/PersonaCore-Agent/releases/download/v1",
		"traversal":              "https://github.com/synssins/PersonaCore-Agent/releases/download/../../../a.zip",
		"encoded traversal":      "https://github.com/synssins/PersonaCore-Agent/releases/download/%2e%2e/%2e%2e/a.zip",
		"malformed port":         "https://github.com:notaport/a.zip",
		"control char":           "https://github.com/\x7f/releases/download/v1/a.zip",
		"cdn as start host":      "https://objects.githubusercontent.com/blob/agent.zip",
		"api as start host":      "https://api.github.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
	} {
		if err := p.CheckArtifactURL(bad); err == nil {
			t.Fatalf("%s: %q should have been rejected", name, bad)
		} else if !strings.HasPrefix(err.Error(), "origin:") {
			t.Fatalf("%s: error should name the policy, got %v", name, err)
		}
	}
}

func TestCheckArtifactURL_ErrorDoesNotLeakCredentials(t *testing.T) {
	p := mustPolicy(t)
	err := p.CheckArtifactURL("https://user:hunter2@evil.example.com/a.zip")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaked credentials: %v", err)
	}
}

func TestCheckAPIURL(t *testing.T) {
	p := mustPolicy(t)
	if err := p.CheckAPIURL(p.APILatestReleaseURL()); err != nil {
		t.Fatalf("our own API URL must pass: %v", err)
	}
	if p.APILatestReleaseURL() !=
		"https://api.github.com/repos/synssins/PersonaCore-Agent/releases/latest" {
		t.Fatalf("unexpected API URL %q", p.APILatestReleaseURL())
	}
	for name, bad := range map[string]string{
		"http":         "http://api.github.com/repos/synssins/PersonaCore-Agent/releases/latest",
		"foreign host": "https://api.evil.example/repos/synssins/PersonaCore-Agent/releases/latest",
		"github.com":   "https://github.com/repos/synssins/PersonaCore-Agent/releases/latest",
		"other repo":   "https://api.github.com/repos/attacker/evil/releases/latest",
		"not /repos":   "https://api.github.com/gists/synssins/PersonaCore-Agent",
		"root":         "https://api.github.com/",
	} {
		if err := p.CheckAPIURL(bad); err == nil {
			t.Fatalf("%s: %q should have been rejected", name, bad)
		}
	}
}

func redirectTo(t *testing.T, target string, hops int) (*http.Request, []*http.Request) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q): %v", target, err)
	}
	via := make([]*http.Request, hops)
	return req, via
}

func TestCheckRedirect_AllowsGitHubUserContent(t *testing.T) {
	p := mustPolicy(t)
	for _, ok := range []string{
		"https://objects.githubusercontent.com/blob/agent.zip",
		"https://github-releases.githubusercontent.com/blob/agent.zip",
		"https://release-assets.githubusercontent.com/blob/agent.zip",
		"https://raw.githubusercontent.com/x",
		"https://github.com/synssins/PersonaCore-Agent/releases/download/v1/a.zip",
		"https://api.github.com/repos/synssins/PersonaCore-Agent/releases/latest",
	} {
		req, via := redirectTo(t, ok, 1)
		if err := p.CheckRedirect(req, via); err != nil {
			t.Fatalf("redirect to %s should be allowed: %v", ok, err)
		}
	}
}

func TestCheckRedirect_Refuses(t *testing.T) {
	p := mustPolicy(t)
	for name, bad := range map[string]string{
		"foreign host":     "https://evil.example.com/payload",
		"downgrade":        "http://objects.githubusercontent.com/blob/agent.zip",
		"suffix lookalike": "https://objects.githubusercontent.com.evil.example/x",
		"apex":             "https://githubusercontent.com/x",
		"odd port":         "https://objects.githubusercontent.com:8443/x",
		"credentials":      "https://a:b@objects.githubusercontent.com/x",
	} {
		req, via := redirectTo(t, bad, 1)
		if err := p.CheckRedirect(req, via); err == nil {
			t.Fatalf("%s: redirect to %q must be refused", name, bad)
		}
	}
}

func TestCheckRedirect_CapsHopCount(t *testing.T) {
	p := mustPolicy(t)
	req, via := redirectTo(t, "https://objects.githubusercontent.com/x", maxRedirects)
	if err := p.CheckRedirect(req, via); err == nil {
		t.Fatal("redirect chain must be capped")
	}
	req, via = redirectTo(t, "https://objects.githubusercontent.com/x", maxRedirects-1)
	if err := p.CheckRedirect(req, via); err != nil {
		t.Fatalf("hop %d should still be allowed: %v", maxRedirects-1, err)
	}
}

func TestCheckRedirect_NilRequest(t *testing.T) {
	p := mustPolicy(t)
	if err := p.CheckRedirect(nil, nil); err == nil {
		t.Fatal("nil redirect target must be refused, not allowed")
	}
}

func TestExtraOrigins(t *testing.T) {
	p := mustPolicy(t, "http://127.0.0.1", "http://localhost")
	for _, ok := range []string{
		"http://127.0.0.1:5051/agent.zip",
		"http://localhost:9/manifest.json",
	} {
		if err := p.CheckArtifactURL(ok); err != nil {
			t.Fatalf("%s should be allowed by the test escape: %v", ok, err)
		}
	}
	// The escape is host-specific: it does not become "allow everything".
	for _, bad := range []string{
		"http://127.0.0.2:5051/agent.zip",
		"http://evil.example.com/agent.zip",
		"https://127.0.0.1/agent.zip",
	} {
		if err := p.CheckArtifactURL(bad); err == nil {
			t.Fatalf("%s must not be allowed", bad)
		}
	}
	req, via := redirectTo(t, "http://127.0.0.1:5051/redirected.zip", 1)
	if err := p.CheckRedirect(req, via); err != nil {
		t.Fatalf("extra origins apply to redirects too: %v", err)
	}
}

func TestNoExtraOriginsByDefault(t *testing.T) {
	// A release build bakes nothing in; the resulting policy must be
	// GitHub-only with no runtime way to widen it.
	if got := ParseOriginList(""); got != nil {
		t.Fatalf("empty ldflag should yield no extra origins, got %v", got)
	}
	if got := ParseOriginList(" , ,"); got != nil {
		t.Fatalf("blank entries should be dropped, got %v", got)
	}
	got := ParseOriginList("http://127.0.0.1, http://localhost ")
	if len(got) != 2 || got[0] != "http://127.0.0.1" || got[1] != "http://localhost" {
		t.Fatalf("ParseOriginList = %v", got)
	}
	if _, err := New(DefaultRepo, []string{"not a url at all::"}); err == nil {
		t.Fatal("a malformed extra origin should be an error, not silently ignored")
	}
	if _, err := New(DefaultRepo, []string{"justahost"}); err == nil {
		t.Fatal("an extra origin without a scheme should be rejected")
	}
}

func TestHarden(t *testing.T) {
	p := mustPolicy(t)
	if c := p.Harden(nil, 0); c.CheckRedirect == nil {
		t.Fatal("Harden(nil) must still install the redirect policy")
	}
	orig := &http.Client{}
	hardened := p.Harden(orig, 0)
	if orig.CheckRedirect != nil {
		t.Fatal("Harden must not mutate the caller's client")
	}
	if hardened == orig {
		t.Fatal("Harden must return a copy")
	}
	if hardened.CheckRedirect == nil {
		t.Fatal("hardened client has no redirect policy")
	}
}
