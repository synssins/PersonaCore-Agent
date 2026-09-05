# PersonaCore-Agent installer builder (SPEC-10).
#
# Runs the full pipeline:
#   1) PyInstaller  ->  dist\Agent\
#   2) go build     ->  dist\Updater.exe   (baking in the Ed25519 pubkey)
#   3) iscc         ->  dist\PersonaCore-Agent-Setup-<version>.exe
#
# Usage:
#     ./installer/build.ps1 -Version 0.1.0
#
# Environment variables:
#     PC_AGENT_SIGNING_PUBKEY   hex-encoded Ed25519 public key baked into
#                               Updater.exe.  When absent, the updater
#                               builds with an empty key (dev only).

param(
    [Parameter(Mandatory = $false)]
    [string]$Version = "0.1.0",

    [Parameter(Mandatory = $false)]
    [string]$Python = ".venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

Write-Host "==> Building PersonaCore-Agent installer v$Version"

# ---------------------------------------------------------------------------
# 1) PyInstaller
# ---------------------------------------------------------------------------
Write-Host "==> [1/3] PyInstaller"

# The stock pyinstaller-hooks-contrib ships a webrtcvad hook that calls
# copy_metadata("webrtcvad"). We ship the module via `webrtcvad-wheels`
# (drop-in binary distribution with a different distribution name), so the
# metadata lookup fails with PackageNotFoundError. Delete the offending
# hook file (and its .pyc) before PyInstaller runs — the module still
# imports fine and workstation_agent.spec hiddenimports webrtcvad explicitly.
try {
    $stdhooksDirRaw = & $Python -c "import os, _pyinstaller_hooks_contrib.stdhooks as m; print(os.path.dirname(m.__file__))" 2>&1
    if ($LASTEXITCODE -eq 0 -and $stdhooksDirRaw) {
        $stdhooksDir = ($stdhooksDirRaw | Out-String).Trim()
        if ($stdhooksDir -and (Test-Path $stdhooksDir)) {
            Get-ChildItem -Path $stdhooksDir -Filter "hook-webrtcvad*" -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Host "    (removed $($_.FullName))"
                Remove-Item -Force $_.FullName -ErrorAction SilentlyContinue
            }
            Get-ChildItem -Path (Join-Path $stdhooksDir "__pycache__") -Filter "hook-webrtcvad*" -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Force $_.FullName -ErrorAction SilentlyContinue
            }
        }
    }
} catch {
    Write-Warning "webrtcvad hook removal skipped: $($_.Exception.Message)"
}

& $Python -m PyInstaller --noconfirm workstation_agent.spec
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

# ---------------------------------------------------------------------------
# 2) Go — Updater.exe
# ---------------------------------------------------------------------------
Write-Host "==> [2/3] go build Updater.exe"
$Pubkey = $env:PC_AGENT_SIGNING_PUBKEY
if (-not $Pubkey) {
    Write-Warning "PC_AGENT_SIGNING_PUBKEY not set; Updater.exe will refuse to run --update."
    $Pubkey = ""
}
Push-Location "updater"
try {
    $LdFlags = "-X main.PublicKeyHex=$Pubkey -X main.UpdaterVersion=$Version -s -w"
    & go build -ldflags $LdFlags -o "..\dist\Updater.exe" .
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# 3) Inno Setup
# ---------------------------------------------------------------------------
Write-Host "==> [3/3] Inno Setup"
$Iscc = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $Iscc) {
    Write-Warning "iscc not on PATH — skipping installer packaging."
    Write-Host "  Install Inno Setup 6+ and re-run to produce the .exe installer."
    exit 0
}
& iscc "/DAppVersion=$Version" "installer\setup.iss"
if ($LASTEXITCODE -ne 0) {
    throw "iscc failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "==> Build complete."
Write-Host "    dist\Agent\                                      PyInstaller bundle"
Write-Host "    dist\Updater.exe                                 Go updater"
Write-Host "    dist\PersonaCore-Agent-Setup-$Version.exe        Installer"
