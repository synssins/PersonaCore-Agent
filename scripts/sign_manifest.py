"""Sign ``manifest.json`` with Ed25519.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Usage::

    python scripts/sign_manifest.py path/to/manifest.json

Reads the hex-encoded private key from the ``PC_AGENT_SIGNING_PRIVATE_KEY``
environment variable, canonicalises the manifest JSON via
:func:`workstation_agent.security.signature.canonical_json`, signs the
canonical bytes with Ed25519, and writes ``manifest.json.sig`` next to
the input file.

The signature is over the *canonical* JSON bytes so the Go updater's
verifier produces the same message using the same canonicalisation
rules (deterministic serialisation, sorted keys, no whitespace).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from nacl.signing import SigningKey

from workstation_agent.security import signature as _sig

_ENV_VAR = "PC_AGENT_SIGNING_PRIVATE_KEY"


def _load_private_key() -> SigningKey:
    """Load the Ed25519 signing key from the env var.

    Returns
    -------
    SigningKey
        Instance backing every :func:`sign` invocation.
    """
    raw = os.environ.get(_ENV_VAR, "").strip()
    if not raw:
        msg = f"env {_ENV_VAR} not set — refusing to sign"
        raise SystemExit(msg)
    try:
        key_bytes = bytes.fromhex(raw)
    except ValueError as exc:
        msg = f"env {_ENV_VAR} is not valid hex: {exc}"
        raise SystemExit(msg) from exc
    if len(key_bytes) != 32:  # noqa: PLR2004
        msg = f"env {_ENV_VAR} must decode to 32 bytes; got {len(key_bytes)}"
        raise SystemExit(msg)
    return SigningKey(key_bytes)


def sign_manifest(manifest_path: Path) -> Path:
    """Sign *manifest_path* and write ``<name>.sig`` next to it."""
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    canonical = _sig.canonical_json(payload)
    signing_key = _load_private_key()
    signed = signing_key.sign(canonical)
    sig_path = manifest_path.with_suffix(manifest_path.suffix + ".sig")
    sig_path.write_bytes(signed.signature)
    return sig_path


def main() -> int:
    p = argparse.ArgumentParser(prog="sign_manifest")
    p.add_argument("manifest", type=Path, help="Path to manifest.json")
    args = p.parse_args()
    try:
        out = sign_manifest(args.manifest)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"sign_manifest: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
