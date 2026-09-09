"""Guard against a defect that broke the release build: a ``.ps1`` file that
is UTF-8 (or any non-ASCII encoding) with no byte-order mark.

Windows PowerShell 5.1 decodes a ``.ps1`` file using the system ANSI codepage
(e.g. cp1252) unless the file starts with a byte-order mark (BOM). A non-ASCII
character written as UTF-8 -- for example an em dash, ``E2 80 94`` -- gets
misread under cp1252 as a sequence of characters that includes stray curly
quotes. PowerShell 5.1 accepts curly quotes as string delimiters, so one such
byte can silently open an unterminated string and blow up the parser dozens
of lines away from the real problem.

``installer/build.ps1`` hit exactly this: three em dashes, no BOM, and the
release build could not run at all (see the SPEC-10/P4 handoff). This test
scans every ``.ps1`` file in the repository and fails if any of them would be
mis-decoded by PowerShell 5.1 -- i.e. contains a non-ASCII byte without a
BOM -- so the defect cannot silently return, including in files added later.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Directories that never contain source we care about (build output, VCS
# metadata, virtual envs, worktree scratch space, etc).
_EXCLUDED_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".pyright_cache",
    ".ruff_cache",
    "__pycache__",
}

UTF8_BOM = b"\xef\xbb\xbf"
UTF16_LE_BOM = b"\xff\xfe"
UTF16_BE_BOM = b"\xfe\xff"


def _is_excluded(path: Path) -> bool:
    return any(part in _EXCLUDED_DIR_NAMES for part in path.parts)


def _discover_ps1_files() -> list[Path]:
    return sorted(
        p
        for p in REPO_ROOT.rglob("*.ps1")
        if not _is_excluded(p.relative_to(REPO_ROOT))
    )


def _has_bom(data: bytes) -> bool:
    return data.startswith((UTF8_BOM, UTF16_LE_BOM, UTF16_BE_BOM))


def _find_non_ascii_byte(data: bytes) -> tuple[int, int] | None:
    """Return (line_number, column_offset) of the first byte >= 0x80, if any."""
    line_no = 1
    line_start = 0
    for i, b in enumerate(data):
        if b == 0x0A:  # \n -- count lines regardless of \r\n or \n
            line_no += 1
            line_start = i + 1
            continue
        if b >= 0x80:
            return line_no, i - line_start
    return None


_PS1_FILES = _discover_ps1_files()


@pytest.mark.parametrize(
    "ps1_path",
    _PS1_FILES,
    ids=[str(p.relative_to(REPO_ROOT)) for p in _PS1_FILES],
)
def test_ps1_file_is_ascii_or_has_bom(ps1_path: Path) -> None:
    """Windows PowerShell 5.1 must be able to decode this file correctly.

    That requires either: the file is pure ASCII (so any single-byte ANSI
    codepage decodes it identically to what was written), or the file opens
    with a byte-order mark that forces correct decoding regardless of the
    system codepage.
    """
    data = ps1_path.read_bytes()

    if _has_bom(data):
        return

    offense = _find_non_ascii_byte(data)
    assert offense is None, (
        f"{ps1_path.relative_to(REPO_ROOT)} contains a non-ASCII byte at "
        f"line {offense[0] if offense else '?'} with no byte-order mark. "
        "Windows PowerShell 5.1 decodes .ps1 files using the system ANSI "
        "codepage unless a BOM is present, so this byte will be misread "
        "(e.g. an em dash can decode to a curly quote, which PowerShell "
        "accepts as a string delimiter and silently corrupts parsing far "
        "from this line). Either add a UTF-8 BOM to the file or replace "
        "the non-ASCII character(s) with ASCII equivalents."
    )


def test_discovers_at_least_one_ps1_file() -> None:
    """Sanity check that the scan itself is not silently finding nothing."""
    assert _PS1_FILES, "expected to find at least one .ps1 file in the repo"
