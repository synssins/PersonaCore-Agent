# ruff: noqa: INP001, T201
"""Generate canonical_json fixtures for the Go cross-check test.

Run with:  python updater/internal/manifest/gen_fixtures.py

Overwrites updater/internal/manifest/testdata/canonical.json.
The Go test loads that file and asserts byte-equality between
its own CanonicalJSON output and the base64-encoded reference here.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from workstation_agent.security.signature import canonical_json

FIXTURES: list[object] = [
    {"a": 1, "b": 2, "c": [1, 2, 3]},
    {"z": "unicode test", "a": None, "b": True, "c": False},
    {},
    [1, 2, 3, {"nested": {"x": 1, "y": [True, False, None]}}],
    {
        "version": "1.2.3",
        "channel": "stable",
        "released_at": "2026-09-15T04:00:00Z",
        "mandatory": False,
        "notes_url": "https://example.invalid/v1.2.3",
        "artifacts": {
            "agent": {
                "url": "https://example.invalid/agent.zip",
                "sha256": "0" * 64,
                "size": 100,
            },
            "updater": {
                "url": "https://example.invalid/updater.exe",
                "sha256": "1" * 64,
                "size": 50,
            },
        },
        "min_updater_version": "1.0.0",
    },
    {"escape": 'a"b\\c\nd\te'},
    {"ctrl": "\x00\x01\x1f"},
]


def main() -> None:
    out = []
    for f in FIXTURES:
        cj = canonical_json(f)
        out.append(
            {
                "input": f,
                "canonical_b64": base64.b64encode(cj).decode("ascii"),
            },
        )
    dest = Path(__file__).parent / "testdata" / "canonical.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {dest} ({len(out)} fixtures)")


if __name__ == "__main__":
    main()
