# Build Updater.exe with the CI-provided Ed25519 public key baked in.
#
# Env vars:
#   PC_AGENT_SIGNING_PUBKEY   - hex-encoded 32-byte Ed25519 public key
#   PC_AGENT_UPDATER_VERSION  - semver string (defaults to 0.0.0-dev)
#
# Output: dist/Updater.exe

param(
    [string]$PubKeyHex = $env:PC_AGENT_SIGNING_PUBKEY,
    [string]$Version   = $(if ($env:PC_AGENT_UPDATER_VERSION) { $env:PC_AGENT_UPDATER_VERSION } else { "0.0.0-dev" })
)

if (-not $PubKeyHex) {
    Write-Warning "PC_AGENT_SIGNING_PUBKEY not set - building a DEV binary with no key."
    $PubKeyHex = ""
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$ldflags = "-X main.PublicKeyHex=$PubKeyHex -X main.UpdaterVersion=$Version -s -w"
& go build -ldflags $ldflags -o dist/Updater.exe .
if ($LASTEXITCODE -ne 0) { throw "go build failed with exit $LASTEXITCODE" }
Get-Item dist/Updater.exe | Select-Object Name, Length, LastWriteTime
