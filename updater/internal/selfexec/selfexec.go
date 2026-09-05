// Package selfexec implements the self-lock-avoidance dance from
// SPEC-06 rule 5.
//
// When the running agent spawns Updater.exe from <install>\current\,
// that binary is memory-mapped and held with a share-deny-write handle
// for its lifetime. If we then try to swap the `current` junction we
// hit ERROR_SHARING_VIOLATION. To avoid that, the FIRST thing the
// updater does on --update / --rollback is copy ITSELF to
// %TEMP%\PC-Agent-Updater-<version>.exe and re-exec from that copy,
// then exit — releasing the original file handle. The temp copy then
// does the real work.
package selfexec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// EnvSentinel is set on the re-execed child so the CLI knows not to
// re-exec a second time. Value is the path of the ORIGINAL binary so
// the child can schedule its own cleanup if needed.
const EnvSentinel = "PC_AGENT_UPDATER_SELF_RELAY"

// RelayIfNeeded copies the current executable to a stable location under
// %TEMP% and re-execs from there. It returns:
//   - (relayed, "", nil)  -> we ARE the relayed child, keep running
//   - (relayed, path, nil) -> we spawned a child successfully; caller
//     should exit 0 immediately without doing any further work.
//   - (_, _, err)         -> unrecoverable, refuse to proceed.
//
// The "relayed" flag lets callers write different log lines depending on
// which side of the relay they are.
//
// version is used for the temp filename so concurrent updater runs
// (should never happen but be safe) don't collide.
func RelayIfNeeded(version string, args []string) (relayed bool, spawnedPath string, err error) {
	if os.Getenv(EnvSentinel) != "" {
		return true, "", nil
	}

	selfPath, err := os.Executable()
	if err != nil {
		return false, "", fmt.Errorf("selfexec: os.Executable: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		// EvalSymlinks may fail on Windows for exes launched via a junction;
		// fall back to the raw path.
		selfPath, _ = os.Executable()
	}

	tempDir := os.TempDir()
	safeVer := sanitizeFilename(version)
	if safeVer == "" {
		safeVer = "unknown"
	}
	copyPath := filepath.Join(tempDir, "PC-Agent-Updater-"+safeVer+".exe")

	if err := copyFile(selfPath, copyPath); err != nil {
		return false, "", fmt.Errorf("selfexec: copy %s -> %s: %w", selfPath, copyPath, err)
	}

	env := append(os.Environ(), EnvSentinel+"="+selfPath)
	cmd := exec.Command(copyPath, args...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return false, "", fmt.Errorf("selfexec: start %s: %w", copyPath, err)
	}
	// Detach — don't wait. The parent must exit so its file handle drops.
	go func() {
		_ = cmd.Wait()
	}()
	return false, copyPath, nil
}

// ScheduleSelfDelete writes a small .bat next to self that waits a
// moment then deletes self+bat. Best-effort; if it fails we return an
// error but the caller usually ignores it because the exe is only a
// few MB of orphaned temp space.
func ScheduleSelfDelete() error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToLower(selfPath), strings.ToLower(os.TempDir())) {
		// Refuse to schedule deletion of anything outside %TEMP%.
		return errors.New("selfexec: refusing to self-delete outside temp dir")
	}
	batPath := selfPath + ".cleanup.bat"
	// Ping-based delay is the classic Windows self-deleter — no external
	// tools required, works on every Windows since XP.
	script := "@echo off\r\n" +
		"ping 127.0.0.1 -n 3 > nul\r\n" +
		"del \"" + selfPath + "\" > nul 2>&1\r\n" +
		"del \"%~f0\" > nul 2>&1\r\n"
	if err := os.WriteFile(batPath, []byte(script), 0o644); err != nil {
		return err
	}
	cmd := exec.Command("cmd.exe", "/c", "start", "", "/b", batPath)
	return cmd.Start()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// Write to a temp file next to dst then rename for atomicity.
	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// If dst exists (from a prior run) remove it first.
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
