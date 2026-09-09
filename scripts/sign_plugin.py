"""Sign a plugin's ``signature.sig`` with the first-party Ed25519 key.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Usage::

    # key from the environment (preferred: nothing touches the shell history)
    PC_AGENT_SIGNING_PRIVATE_KEY=<hex> \\
        python scripts/sign_plugin.py src/workstation_agent/plugins/browser ...

    # or point at the hex file directly (the file itself is never committed)
    python scripts/sign_plugin.py --key-file working/signing/first_party.priv.hex \\
        src/workstation_agent/plugins/browser ...

    # re-sign every bundled plugin that already carries a real signature
    python scripts/sign_plugin.py --all-bundled

The message signed is produced by
:func:`workstation_agent.mcp_host.loader.signing_message` — the very function
the loader verifies against — so the signer cannot drift from the verifier.  In
particular the hash is newline-normalised for ``*.py`` files, which is what
makes a signature valid under every ``core.autocrlf`` setting rather than only
in the checkout that produced it.

Safety rails:

* A plugin whose ``signature.sig`` currently holds the ``UNSIGNED`` sentinel (or
  is empty) is **skipped**, so the deliberately-unsigned canaries
  (``hello_world``, ``claude_code_bridge``) cannot be signed by accident.  Pass
  ``--replace-sentinel`` to override for a specific directory.
* The private key is never echoed.  The derived *public* key is printed so the
  operator can confirm which identity signed.
* Every signature written is verified before the script exits non-zero/zero.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from nacl.signing import SigningKey

from workstation_agent.mcp_host import loader as _loader

_ENV_VAR = "PC_AGENT_SIGNING_PRIVATE_KEY"
_KEY_BYTES = 32
_SENTINELS = (b"", b"UNSIGNED")
_BUNDLED_DIR = Path(__file__).resolve().parents[1] / "src" / "workstation_agent" / "plugins"


def _load_signing_key(key_file: Path | None) -> SigningKey:
    """Return the Ed25519 signing key from *key_file* or the environment."""
    if key_file is not None:
        raw = key_file.read_text(encoding="utf-8").strip()
        origin = str(key_file)
    else:
        raw = os.environ.get(_ENV_VAR, "").strip()
        origin = f"env {_ENV_VAR}"
    if not raw:
        msg = f"no private key: set {_ENV_VAR} or pass --key-file"
        raise SystemExit(msg)
    try:
        key_bytes = bytes.fromhex(raw)
    except ValueError as exc:
        msg = f"{origin} is not valid hex: {exc}"
        raise SystemExit(msg) from exc
    if len(key_bytes) != _KEY_BYTES:
        msg = f"{origin} must decode to {_KEY_BYTES} bytes; got {len(key_bytes)}"
        raise SystemExit(msg)
    return SigningKey(key_bytes)


def sign_plugin(
    plugin_dir: Path,
    signing_key: SigningKey,
    *,
    replace_sentinel: bool = False,
) -> str:
    """Sign the plugin at *plugin_dir*; return a one-line status for the caller."""
    toml_path = plugin_dir / "plugin.toml"
    if not toml_path.is_file():
        return f"SKIP  {plugin_dir.name}: no plugin.toml"

    sig_path = plugin_dir / "signature.sig"
    if sig_path.exists() and sig_path.read_bytes() in _SENTINELS and not replace_sentinel:
        return f"SKIP  {plugin_dir.name}: sentinel-unsigned (use --replace-sentinel to force)"

    manifest = _loader._parse_toml(toml_path, source="signing")  # noqa: SLF001
    if manifest is None:
        return f"FAIL  {plugin_dir.name}: plugin.toml did not parse"

    message = _loader.signing_message(manifest)
    signature = signing_key.sign(message).signature
    sig_path.write_bytes(signature)

    pubkey = bytes(signing_key.verify_key)
    result = _loader.verify(manifest, [pubkey], allow_unsigned=False)
    if result.status != "valid":
        return f"FAIL  {plugin_dir.name}: wrote signature but verify said {result.status}"
    covered = _loader._covered_files(manifest.entry, manifest.plugin_dir)  # noqa: SLF001
    names = ", ".join(label for label, _path in covered)
    return f"OK    {plugin_dir.name}: signed over {len(covered)} file(s) [{names}]"


def main() -> int:
    p = argparse.ArgumentParser(prog="sign_plugin")
    p.add_argument("plugin_dir", type=Path, nargs="*", help="plugin directories to sign")
    p.add_argument(
        "--all-bundled",
        action="store_true",
        help="sign every bundled plugin that is not sentinel-unsigned",
    )
    p.add_argument(
        "--key-file",
        type=Path,
        default=None,
        help=f"hex-encoded Ed25519 private key file (default: ${_ENV_VAR})",
    )
    p.add_argument(
        "--replace-sentinel",
        action="store_true",
        help="also sign plugins whose signature.sig currently holds the UNSIGNED sentinel",
    )
    args = p.parse_args()

    targets: list[Path] = list(args.plugin_dir)
    if args.all_bundled:
        targets.extend(sorted(d for d in _BUNDLED_DIR.iterdir() if (d / "plugin.toml").is_file()))
    if not targets:
        p.error("nothing to sign: pass plugin directories or --all-bundled")

    signing_key = _load_signing_key(args.key_file)
    print(f"signing identity (public key): {bytes(signing_key.verify_key).hex()}")

    failed = False
    for target in targets:
        try:
            line = sign_plugin(
                target.resolve(), signing_key, replace_sentinel=args.replace_sentinel,
            )
        except Exception as exc:  # noqa: BLE001
            line = f"FAIL  {target.name}: {exc}"
        print(line)
        failed = failed or line.startswith("FAIL")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
