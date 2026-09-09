// Package origin pins update traffic to the project's own GitHub repo.
//
// The updater downloads code that it then executes, so the set of hosts it
// will talk to is part of the trust boundary — not something the (attacker
// influenceable) manifest gets to choose. A signature makes a forged manifest
// hard; pinning the origin makes an unsigned-path mistake, a downgraded
// signature check, or a tampered manifest field unable to point the download
// anywhere but GitHub's release hosting for one specific repository.
//
// Two stages, deliberately different:
//
//	Stage 1 — the URL we are handed (from the manifest, or from the GitHub
//	API payload). It must be an exact, https-only, default-port
//	https://github.com/<owner>/<repo>/releases/download/... URL for the
//	pinned repo (or, for the manifest feed, https://api.github.com/repos/
//	<owner>/<repo>/...). Nothing else starts a request.
//
//	Stage 2 — every hop of the redirect chain. GitHub does not serve release
//	bytes from github.com: a release-asset request 302s to GitHub's
//	user-content CDN, whose hostname has changed over the years
//	(objects.githubusercontent.com, github-releases.githubusercontent.com,
//	release-assets.githubusercontent.com …). So redirects may land on
//	github.com, api.github.com, or any host under githubusercontent.com —
//	a namespace GitHub allocates, not one users can claim — over https on
//	the default port, and nowhere else. A redirect off that set is an error,
//	never a silent fallback.
//
// The pin is compile-time configurable (see Repo in main.go, set with
// -ldflags -X) so a fork can build its own updater, and never reads anything
// out of the payload it is validating.
package origin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxRedirects caps the hop count independently of net/http's own limit.
const maxRedirects = 5

// DefaultRepo is the repository this project's updates come from. Overridden
// at build time via -ldflags "-X main.Repo=owner/name" for forks.
const DefaultRepo = "synssins/PersonaCore-Agent"

const (
	hostGitHub    = "github.com"
	hostGitHubAPI = "api.github.com"
	// userContentSuffix covers objects./github-releases./release-assets.
	// githubusercontent.com — GitHub allocates every label under this
	// domain, so the set stays GitHub-operated even as the name churns.
	userContentSuffix = ".githubusercontent.com"
)

// Policy is an immutable origin pin. The zero value is unusable; build one
// with New.
type Policy struct {
	owner string
	name  string
	// extra are development/test escapes. They are empty in a release build
	// and can only be populated by this process's own code (a build-time
	// ldflag on the Go side), never by a fetched payload.
	extra []extraOrigin
}

type extraOrigin struct {
	scheme string
	host   string // lower-case, no port; any port is accepted
}

// New builds a Policy pinned to repo ("owner/name").
//
// extraOrigins is a list of "scheme://host" strings (port ignored / any port
// allowed) that are additionally permitted at both stages. It exists so the
// test-suite can point a freshly built updater at a local HTTP fixture
// server; a shipped build passes none and is therefore GitHub-only.
func New(repo string, extraOrigins []string) (*Policy, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return nil, err
	}
	p := &Policy{owner: owner, name: name}
	for _, raw := range extraOrigins {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, perr := url.Parse(raw)
		if perr != nil {
			return nil, fmt.Errorf("origin: bad extra origin %q: %w", raw, perr)
		}
		host := normaliseHost(u.Hostname())
		if u.Scheme == "" || host == "" {
			return nil, fmt.Errorf("origin: extra origin %q must be scheme://host", raw)
		}
		p.extra = append(p.extra, extraOrigin{scheme: strings.ToLower(u.Scheme), host: host})
	}
	return p, nil
}

// ParseOriginList splits a comma-separated origin list (as baked in by
// -ldflags) into its entries. Empty input yields nil.
func ParseOriginList(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Repo returns the pinned "owner/name".
func (p *Policy) Repo() string { return p.owner + "/" + p.name }

// APILatestReleaseURL is the only manifest feed this policy will fetch.
func (p *Policy) APILatestReleaseURL() string {
	return "https://" + hostGitHubAPI + "/repos/" + p.Repo() + "/releases/latest"
}

func badRepoSegment(s string) bool {
	if s == "" || len(s) > 100 {
		return true
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return true
		}
	}
	// "." and ".." would let a path segment escape the pinned prefix.
	return s == "." || s == ".."
}

func splitRepo(repo string) (owner, name string, err error) {
	owner, name, found := strings.Cut(strings.TrimSpace(repo), "/")
	if !found || badRepoSegment(owner) || badRepoSegment(name) {
		return "", "", fmt.Errorf(
			"origin: repo pin %q must be \"owner/name\" using [A-Za-z0-9._-]", repo)
	}
	return owner, name, nil
}

func normaliseHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// parseStrict parses raw and rejects the shapes we never want to see at all,
// whichever stage we are in.
func parseStrict(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("origin: unparseable URL %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("origin: %q is not an absolute URL", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("origin: refusing URL with embedded credentials: %s", redact(u))
	}
	return u, nil
}

func redact(u *url.URL) string {
	c := *u
	c.User = nil
	c.RawQuery = ""
	c.Fragment = ""
	return c.String()
}

// matchesExtra reports whether u is covered by a development/test escape.
func (p *Policy) matchesExtra(u *url.URL) bool {
	host := normaliseHost(u.Hostname())
	scheme := strings.ToLower(u.Scheme)
	for _, e := range p.extra {
		if e.scheme == scheme && e.host == host {
			return true
		}
	}
	return false
}

// requireGitHubHTTPS enforces https, the default port, and one of the
// permitted GitHub hostnames for the given stage.
func requireGitHubHTTPS(u *url.URL, allow func(host string) bool, what string) error {
	if strings.ToLower(u.Scheme) != "https" {
		return fmt.Errorf(
			"origin: %s must use https (got %q in %s)", what, u.Scheme, redact(u))
	}
	if port := u.Port(); port != "" && port != "443" {
		return fmt.Errorf("origin: %s must use the default https port (got :%s)", what, port)
	}
	host := normaliseHost(u.Hostname())
	if !allow(host) {
		return fmt.Errorf("origin: %s host %q is not the pinned update source", what, host)
	}
	return nil
}

func isStartHost(host string) bool {
	return host == hostGitHub || host == hostGitHubAPI
}

func isRedirectHost(host string) bool {
	if isStartHost(host) {
		return true
	}
	// Sub-domains only; the bare apex is not a release host and refusing it
	// costs us nothing.
	return strings.HasSuffix(host, userContentSuffix) &&
		len(host) > len(userContentSuffix)
}

// pathSegments returns the decoded path segments, or an error if the path
// contains a traversal segment.
func pathSegments(u *url.URL) ([]string, error) {
	raw := strings.Trim(u.EscapedPath(), "/")
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		dec, err := url.PathUnescape(p)
		if err != nil {
			return nil, fmt.Errorf("origin: undecodable path segment %q", p)
		}
		if dec == "." || dec == ".." || strings.ContainsAny(dec, "/\\") {
			return nil, fmt.Errorf("origin: refusing path traversal in %s", redact(u))
		}
		out = append(out, dec)
	}
	return out, nil
}

func (p *Policy) repoMatches(owner, name string) bool {
	// GitHub treats owner/repo case-insensitively and will redirect a
	// mis-cased URL to the canonical one; accept either spelling rather
	// than failing an update over capitalisation.
	return strings.EqualFold(owner, p.owner) && strings.EqualFold(name, p.name)
}

// CheckArtifactURL validates a URL we are about to start a download from: a
// release asset of the pinned repository, https, github.com, default port.
//
// It is the stage-1 gate for anything the manifest (or the GitHub API
// payload, which is equally untrusted) names.
func (p *Policy) CheckArtifactURL(raw string) error {
	u, err := parseStrict(raw)
	if err != nil {
		return err
	}
	if p.matchesExtra(u) {
		return nil
	}
	if err := requireGitHubHTTPS(u, func(h string) bool { return h == hostGitHub },
		"update artifact URL"); err != nil {
		return err
	}
	segs, err := pathSegments(u)
	if err != nil {
		return err
	}
	// /<owner>/<repo>/releases/download/<tag>/<asset>
	const minSegs = 6
	if len(segs) < minSegs || !p.repoMatches(segs[0], segs[1]) ||
		segs[2] != "releases" || segs[3] != "download" {
		return fmt.Errorf(
			"origin: update artifact URL %s is not a release download of %s",
			redact(u), p.Repo())
	}
	return nil
}

// CheckAPIURL validates a GitHub REST URL for the pinned repository.
func (p *Policy) CheckAPIURL(raw string) error {
	u, err := parseStrict(raw)
	if err != nil {
		return err
	}
	if p.matchesExtra(u) {
		return nil
	}
	if err := requireGitHubHTTPS(u, func(h string) bool { return h == hostGitHubAPI },
		"update manifest API URL"); err != nil {
		return err
	}
	segs, err := pathSegments(u)
	if err != nil {
		return err
	}
	const minSegs = 3
	if len(segs) < minSegs || segs[0] != "repos" || !p.repoMatches(segs[1], segs[2]) {
		return fmt.Errorf("origin: manifest API URL %s is not scoped to %s",
			redact(u), p.Repo())
	}
	return nil
}

// CheckRedirect is an http.Client CheckRedirect hook. Stage 2: the hop must
// stay on github.com, api.github.com or GitHub's user-content CDN, over https.
func (p *Policy) CheckRedirect(req *http.Request, via []*http.Request) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("origin: redirect with no target URL")
	}
	if len(via) >= maxRedirects {
		return fmt.Errorf("origin: too many redirects (%d) fetching update", len(via))
	}
	if req.URL.User != nil {
		return fmt.Errorf("origin: refusing redirect with embedded credentials")
	}
	if p.matchesExtra(req.URL) {
		return nil
	}
	return requireGitHubHTTPS(req.URL, isRedirectHost, "update redirect")
}

// Harden returns a copy of client whose redirect policy is this Policy's.
// A nil client yields a fresh one with the given timeout. Copying rather than
// mutating means a caller that forgot to pin its client still gets a pinned
// request, and a caller that shares a client does not have it changed
// underneath it.
func (p *Policy) Harden(client *http.Client, timeout time.Duration) *http.Client {
	var c http.Client
	if client != nil {
		c = *client // shallow: Transport/Jar are shared on purpose
	} else {
		c.Timeout = timeout
	}
	c.CheckRedirect = p.CheckRedirect
	return &c
}
