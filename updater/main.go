// Command Updater is the standalone Windows self-updater binary for
// PersonaCore-Agent. It has no Python runtime — it reads
// pending_update.json (written by the running agent), verifies the
// baked-in Ed25519 pubkey against the signature, downloads the new
// artifact, and atomically swaps the install root.
//
// See SPEC-06 for the detailed contract.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/synssins/PersonaCore-Agent/updater/internal/logging"
	"github.com/synssins/PersonaCore-Agent/updater/internal/manifest"
	"github.com/synssins/PersonaCore-Agent/updater/internal/prune"
	"github.com/synssins/PersonaCore-Agent/updater/internal/selfexec"
	"github.com/synssins/PersonaCore-Agent/updater/internal/swap"
	"github.com/synssins/PersonaCore-Agent/updater/internal/verify"
)

// PublicKeyHex is baked in at build time via:
//
//	-ldflags "-X main.PublicKeyHex=<hex>"
//
// In tests it's overridden by the test harness. Empty at dev-mode build
// time; --check / --update will refuse to run without a key.
var PublicKeyHex = ""

// UpdaterVersion is stamped in the same way (defaults for dev builds).
var UpdaterVersion = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("Updater", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we produce our own error messages
	update := fs.Bool("update", false, "apply the pending update")
	rollbackVer := fs.String("rollback", "", "roll back to the given version")
	check := fs.Bool("check", false, "fetch and verify latest manifest, print, exit")
	installRoot := fs.String("install-root", "", "override install root (tests)")
	pendingPath := fs.String("pending", "", "override pending_update.json path (tests)")
	pubkeyOverride := fs.String("pubkey-hex", "", "override baked pubkey (tests)")
	logsDirFlag := fs.String("logs-dir", "", "override log directory (tests)")
	keepN := fs.Int("keep", 3, "how many old versions to retain when pruning")
	// URL used by --check; overridable so we don't require a live GitHub call.
	checkManifest := fs.String("check-manifest", "", "URL to the manifest.json to check")
	checkSig := fs.String("check-sig", "", "URL to the manifest.json.sig to check")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "parse args:", err)
		return 2
	}

	// Logging goes to file first; console echo remains for tests.
	dir := *logsDirFlag
	if dir == "" {
		dir = logging.DefaultLogsDir()
	}
	log, err := logging.New(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logging init:", err)
		// Fall back to stderr-only.
		log, _ = logging.New("")
	}
	defer log.Close()

	pubkeyHex := PublicKeyHex
	if *pubkeyOverride != "" {
		pubkeyHex = *pubkeyOverride
	}

	switch {
	case *check:
		return cmdCheck(log, pubkeyHex, *checkManifest, *checkSig)
	case *rollbackVer != "":
		return cmdRollback(log, *installRoot, *rollbackVer, *keepN)
	case *update:
		return cmdUpdate(log, pubkeyHex, *installRoot, *pendingPath, *keepN)
	default:
		fmt.Fprintln(os.Stderr, "usage: Updater --update | --rollback <ver> | --check")
		return 2
	}
}

// resolveInstallRoot picks the install root the updater is operating on.
// Precedence: --install-root, PC_AGENT_INSTALL_ROOT env, else grandparent
// of this exe (…\current\Updater.exe -> …).
func resolveInstallRoot(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	if v := os.Getenv("PC_AGENT_INSTALL_ROOT"); v != "" {
		return filepath.Abs(v)
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	// self = …\current\Updater.exe   OR   %TEMP%\PC-Agent-Updater-x.y.z.exe
	// The relayed temp copy can't infer the root, so require env / flag then.
	return filepath.Abs(filepath.Join(filepath.Dir(self), "..", ".."))
}

func resolvePendingPath(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	if v := os.Getenv("PC_AGENT_APPDATA"); v != "" {
		return filepath.Join(v, "pending_update.json"), nil
	}
	if v := os.Getenv("APPDATA"); v != "" {
		return filepath.Join(v, "WorkstationAgent", "pending_update.json"), nil
	}
	return "", fmt.Errorf("no APPDATA or --pending override provided")
}

func cmdUpdate(log *logging.Logger, pubkeyHex, installOverride, pendingOverride string, keep int) int {
	pendingPath, err := resolvePendingPath(pendingOverride)
	if err != nil {
		log.Error("update: %v", err)
		return 1
	}
	pending, manifestBytes, sigBytes, err := swap.LoadPending(pendingPath)
	if err != nil {
		log.Error("update: %v", err)
		return 1
	}
	m := &pending.Manifest

	// Self-relay so we can swap `current` without holding it open.
	relayed, spawned, err := selfexec.RelayIfNeeded(m.Version, os.Args[1:])
	if err != nil {
		log.Error("update: self-relay: %v", err)
		return 1
	}
	if !relayed {
		log.Info("update: relayed self to %s, exiting parent", spawned)
		return 0
	}
	log.Info("update: relayed child running for version %s", m.Version)

	// Verify signature against baked pubkey.
	if pubkeyHex == "" {
		log.Error("update: no public key baked into this build")
		return 1
	}
	pubkey, err := verify.DecodeKeyHex(pubkeyHex)
	if err != nil {
		log.Error("update: pubkey decode: %v", err)
		return 1
	}
	if !verify.Verify(pubkey, manifestBytes, sigBytes) {
		log.Error("update: signature verification FAILED")
		return 1
	}
	log.Info("update: signature OK for version %s", m.Version)

	installRoot, err := resolveInstallRoot(installOverride)
	if err != nil {
		log.Error("update: resolve install root: %v", err)
		return 1
	}
	layout := swap.InstallLayout{Root: installRoot}

	// Wait for old agent to exit (30s grace).
	if pending.AgentPID != 0 {
		log.Info("update: waiting for agent pid %d to exit", pending.AgentPID)
		if err := swap.WaitForPidExit(pending.AgentPID, 30*time.Second); err != nil {
			log.Warn("update: waitForPidExit: %v (continuing)", err)
		}
	}

	// Download agent artifact into _incoming.
	incoming, err := swap.EnsureIncoming(layout)
	if err != nil {
		log.Error("update: prep incoming: %v", err)
		return 1
	}
	agentZip := filepath.Join(incoming, "agent.zip")
	client := &http.Client{Timeout: 15 * time.Minute}
	log.Info("update: downloading %s", m.Artifacts.Agent.URL)
	if _, err := swap.Download(client, m.Artifacts.Agent.URL, agentZip, m.Artifacts.Agent.SHA256); err != nil {
		log.Error("update: download agent: %v", err)
		return 1
	}
	log.Info("update: sha256 verified, extracting to app\\%s", m.Version)
	target := layout.VersionDir(m.Version)
	// Fresh install path — remove any partial prior extract.
	_ = os.RemoveAll(target)
	if err := swap.ExtractZip(agentZip, target); err != nil {
		log.Error("update: extract: %v", err)
		return 1
	}
	// Swap `current` junction.
	previous, err := swap.SwapTo(layout, m.Version)
	if err != nil {
		log.Error("update: swap junction: %v (previous=%s left untouched)", err, previous)
		return 1
	}
	log.Info("update: junction swapped %s -> %s", previous, m.Version)

	// Relaunch agent.
	pid, err := swap.Relaunch(layout, []string{"--autostart"})
	if err != nil {
		log.Error("update: relaunch failed: %v", err)
		// Best-effort rollback if we can find a previous.
		if previous != "" {
			if _, rerr := swap.SwapTo(layout, previous); rerr != nil {
				log.Error("update: rollback swap FAILED: %v", rerr)
			} else {
				log.Warn("update: rolled back to %s after relaunch failure", previous)
			}
		}
		return 1
	}
	log.Info("update: relaunched agent pid=%d", pid)

	// Prune older versions, always keeping current + previous.
	always := []string{m.Version}
	if previous != "" {
		always = append(always, previous)
	}
	deleted, err := prune.KeepNewest(layout.AppDir(), keep, always)
	if err != nil {
		log.Warn("update: prune: %v", err)
	} else if len(deleted) > 0 {
		log.Info("update: pruned %v", deleted)
	}

	// Delete the pending file — we're done with it.
	if err := os.Remove(pendingPath); err != nil {
		log.Warn("update: remove pending file: %v", err)
	}

	// Schedule self-deletion of the temp copy.
	if err := selfexec.ScheduleSelfDelete(); err != nil {
		log.Warn("update: schedule self-delete: %v", err)
	}
	log.Info("update: done")
	return 0
}

func cmdRollback(log *logging.Logger, installOverride, targetVersion string, keep int) int {
	// Self-relay first so the junction swap doesn't fight with our own image.
	relayed, spawned, err := selfexec.RelayIfNeeded(targetVersion, os.Args[1:])
	if err != nil {
		log.Error("rollback: self-relay: %v", err)
		return 1
	}
	if !relayed {
		log.Info("rollback: relayed self to %s, exiting parent", spawned)
		return 0
	}
	installRoot, err := resolveInstallRoot(installOverride)
	if err != nil {
		log.Error("rollback: resolve install root: %v", err)
		return 1
	}
	layout := swap.InstallLayout{Root: installRoot}
	target := layout.VersionDir(targetVersion)
	if _, err := os.Stat(target); err != nil {
		log.Error("rollback: target version %s not installed: %v", targetVersion, err)
		return 1
	}
	previous, err := swap.SwapTo(layout, targetVersion)
	if err != nil {
		log.Error("rollback: swap: %v", err)
		return 1
	}
	log.Info("rollback: junction %s -> %s", previous, targetVersion)
	pid, err := swap.Relaunch(layout, []string{"--autostart"})
	if err != nil {
		log.Error("rollback: relaunch failed: %v", err)
		return 1
	}
	log.Info("rollback: relaunched agent pid=%d", pid)
	// Prune, always keeping the two visible versions.
	always := []string{targetVersion}
	if previous != "" && previous != targetVersion {
		always = append(always, previous)
	}
	if _, err := prune.KeepNewest(layout.AppDir(), keep, always); err != nil {
		log.Warn("rollback: prune: %v", err)
	}
	_ = selfexec.ScheduleSelfDelete()
	return 0
}

func cmdCheck(log *logging.Logger, pubkeyHex, manifestURL, sigURL string) int {
	if pubkeyHex == "" {
		fmt.Fprintln(os.Stderr, "no public key baked in")
		return 1
	}
	if manifestURL == "" || sigURL == "" {
		fmt.Fprintln(os.Stderr, "--check requires --check-manifest and --check-sig URLs")
		return 2
	}
	client := &http.Client{Timeout: 30 * time.Second}
	mBytes, err := httpGetBytes(client, manifestURL)
	if err != nil {
		log.Error("check: manifest: %v", err)
		return 1
	}
	sBytes, err := httpGetBytes(client, sigURL)
	if err != nil {
		log.Error("check: sig: %v", err)
		return 1
	}
	pubkey, err := verify.DecodeKeyHex(pubkeyHex)
	if err != nil {
		log.Error("check: pubkey: %v", err)
		return 1
	}
	if !verify.Verify(pubkey, mBytes, sBytes) {
		log.Error("check: signature INVALID")
		fmt.Println("INVALID")
		return 1
	}
	m, err := manifest.Parse(mBytes)
	if err != nil {
		log.Error("check: parse: %v", err)
		return 1
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	fmt.Println(string(out))
	return 0
}

func httpGetBytes(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}
