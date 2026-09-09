# Build Updater.exe with the CI-provided Ed25519 public key baked in.
#
# Env vars:
#   PC_AGENT_SIGNING_PUBKEY   - hex-encoded 32-byte Ed25519 public key
#   PC_AGENT_UPDATER_VERSION  - semver string (defaults to 0.0.0-dev)
#   PC_AGENT_UPDATE_REPO      - "owner/name" the updater will accept downloads
#                               from. Optional; defaults (in main.go) to this
#                               project's repo. Forks set it here, at BUILD
#                               time - there is deliberately no runtime knob.
#
# Output: dist/Updater.exe

param(
    [string]$PubKeyHex = $env:PC_AGENT_SIGNING_PUBKEY,
    [string]$Version   = $(if ($env:PC_AGENT_UPDATER_VERSION) { $env:PC_AGENT_UPDATER_VERSION } else { "0.0.0-dev" }),
    [string]$UpdateRepo = $env:PC_AGENT_UPDATE_REPO
)

if (-not $PubKeyHex) {
    Write-Warning "PC_AGENT_SIGNING_PUBKEY not set - building a DEV binary with no key."
    $PubKeyHex = ""
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$ldflags = "-X main.PublicKeyHex=$PubKeyHex -X main.UpdaterVersion=$Version -s -w"
if ($UpdateRepo) {
    if ($UpdateRepo -notmatch '^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$') {
        throw "PC_AGENT_UPDATE_REPO must be 'owner/name', got '$UpdateRepo'"
    }
    Write-Host "Pinning updates to $UpdateRepo"
    $ldflags = "$ldflags -X main.Repo=$UpdateRepo"
}
& go build -ldflags $ldflags -o dist/Updater.exe .
if ($LASTEXITCODE -ne 0) { throw "go build failed with exit $LASTEXITCODE" }
Get-Item dist/Updater.exe | Select-Object Name, Length, LastWriteTime
