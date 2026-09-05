// Package manifest mirrors the Python UpdateManifest schema (design §4.7)
// and provides a canonical-JSON serialisation that MUST byte-match the
// Python side (workstation_agent.security.signature.canonical_json).
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ArtifactRef is a downloadable artifact — either the agent zip or the
// updater exe. Fields must match the Python model exactly (name + order
// don't matter for JSON; only the tag names).
type ArtifactRef struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ArtifactSet holds both artifacts referenced by a manifest.
type ArtifactSet struct {
	Agent   ArtifactRef `json:"agent"`
	Updater ArtifactRef `json:"updater"`
}

// UpdateManifest matches design §4.7.
type UpdateManifest struct {
	Version           string      `json:"version"`
	Channel           string      `json:"channel"`
	ReleasedAt        string      `json:"released_at"`
	Mandatory         bool        `json:"mandatory"`
	NotesURL          string      `json:"notes_url"`
	Artifacts         ArtifactSet `json:"artifacts"`
	MinUpdaterVersion string      `json:"min_updater_version"`
}

// Parse decodes a manifest from JSON bytes with strict unknown-field checks.
func Parse(raw []byte) (*UpdateManifest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m UpdateManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}
	return &m, nil
}

// CanonicalJSON produces byte-identical output to Python's
// workstation_agent.security.signature.canonical_json.
//
// Rules (verified against the Python fixture):
//   - Object keys sorted lexicographically (by UTF-16 code units — but since
//     all our keys are pure ASCII in every real manifest, plain string
//     compare is equivalent).
//   - Separators ',' and ':' with NO surrounding whitespace.
//   - UTF-8 output, no BOM, no trailing newline.
//   - ensure_ascii=False in Python: non-ASCII code points passed through
//     as raw UTF-8. Only the mandatory escapes are applied:
//     '"', '\\', control chars U+0000..U+001F.
//   - No NaN / Infinity (returns an error).
//   - Integers rendered without exponent or trailing zero.
//   - Floats rendered via Python's shortest-repr (matches strconv 'g').
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		writeString(buf, x)
		return nil
	case json.Number:
		buf.WriteString(x.String())
		return nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("canonical_json: NaN/Inf not allowed")
		}
		if x == math.Trunc(x) && !math.Signbit(x) && math.Abs(x) < 1e16 {
			buf.WriteString(strconv.FormatInt(int64(x), 10))
			return nil
		}
		buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
		return nil
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		// Fall back through the JSON round-trip so struct types
		// (like UpdateManifest) become map[string]any and re-enter
		// this switch with deterministic ordering.
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("canonical_json: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var generic any
		if err := dec.Decode(&generic); err != nil {
			return fmt.Errorf("canonical_json: %w", err)
		}
		return encodeCanonical(buf, generic)
	}
}

func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			// Pass through as UTF-8 — matches Python's ensure_ascii=False.
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

var versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$`)

// ParseVersion returns (major, minor, patch) or an error.
func ParseVersion(v string) (int, int, int, error) {
	if !versionRE.MatchString(v) {
		return 0, 0, 0, fmt.Errorf("invalid version %q", v)
	}
	core := v
	if i := strings.IndexAny(v, "-+"); i > 0 {
		core = v[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid version %q", v)
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	pat, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0, fmt.Errorf("invalid version %q", v)
	}
	return maj, min, pat, nil
}

// IsNewer returns true if a > b using numeric semver comparison.
func IsNewer(a, b string) (bool, error) {
	aM, aN, aP, err := ParseVersion(a)
	if err != nil {
		return false, err
	}
	bM, bN, bP, err := ParseVersion(b)
	if err != nil {
		return false, err
	}
	switch {
	case aM != bM:
		return aM > bM, nil
	case aN != bN:
		return aN > bN, nil
	default:
		return aP > bP, nil
	}
}
