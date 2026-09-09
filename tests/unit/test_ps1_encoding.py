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

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Directories that never contain source we care about (build output, VCS
# metadata, virtual envs, worktree scratch space, etc).
#
# ``.claude`` is here because of a real defect: this repo's executor
# workflow creates sibling git worktrees under ``.claude/worktrees/`` (one
# per in-flight subtask), each a full nested checkout with its own copies
# of ``installer/build.ps1`` and ``updater/build.ps1``. Pytest's
# ``norecursedirs`` keeps ``.claude`` out of *test file* discovery, but it
# has no effect on this test's own filesystem walk -- a plain ``rglob``
# does not know or care about that setting, so on a machine with several
# stale worktrees lying around, the walk found (and parametrised on) every
# one of their duplicate ``.ps1`` files. That made the suite's size and
# content depend on how many worktrees happened to exist on the box, and
# meant a malformed ``.ps1`` in someone else's abandoned worktree could
# fail *this* project's test suite under a path that looks like ours and
# is not. ``_discover_ps1_files`` now prefers asking git what this
# checkout actually tracks (see below), which sidesteps the problem
# entirely; this exclusion set is kept as the fallback's safety net for a
# checkout with no git available, so it needs to name every kind of
# directory that must never contribute a file either way.
_EXCLUDED_DIR_NAMES = {
    ".git",
    ".claude",
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


def _discover_ps1_files_via_git() -> list[Path] | None:
    """Ask git which ``*.ps1`` files belong to this checkout, if git is available.

    Preferred over a filesystem walk: ``git ls-files`` reports exactly the
    files that belong to *this* worktree, so a sibling worktree nested
    under ``.claude/worktrees/`` -- a full separate checkout that happens to
    live inside this directory tree -- never contributes a duplicate, no
    matter how many of them exist on the machine. ``.claude/`` is not
    itself listed in ``.gitignore``, so this does not rely on that: each
    nested worktree has its own ``.git`` entry, and git treats any
    directory containing one as another repository's boundary that it does
    not walk into for ``ls-files`` -- confirmed empirically (a file placed
    inside a throwaway nested repo does not appear in ``--others`` output
    even though ``git check-ignore`` reports it is not ignored by any
    pattern). That is precisely the defect this module used to have; see
    the comment on ``_EXCLUDED_DIR_NAMES``.

    ``--cached --others --exclude-standard`` together cover both tracked
    files and a ``.ps1`` file the author just wrote -- added to the working
    tree but not yet ``git add``ed -- while ``--exclude-standard`` still
    keeps out anything actually gitignored. ``--others`` on its own would
    *replace* the tracked listing rather than add to it, which is why
    ``--cached`` is explicit here rather than assumed as a default. Without
    covering the untracked case, a newly written file would silently pass
    locally and only be caught later by CI on a fresh clone, once it is
    already tracked -- exactly the moment the author most wants the check
    to fire.

    Returns ``None`` (never an empty list) when git itself cannot be run --
    no ``git`` executable, not a git checkout at all (e.g. a source
    tarball on a build box) -- so the caller can fall back to a filtered
    walk instead of silently reporting zero files.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.ps1"],  # noqa: S607
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    names = [n for n in result.stdout.decode("utf-8", errors="replace").split("\0") if n]
    return sorted(REPO_ROOT / n for n in names)


def _discover_ps1_files_via_walk() -> list[Path]:
    """Fallback for a checkout with no git available: a filtered filesystem walk.

    Only used when :func:`_discover_ps1_files_via_git` returns ``None``.
    Excludes every directory in ``_EXCLUDED_DIR_NAMES`` -- see that set's
    comment for why ``.claude`` in particular has to be on it.
    """
    return sorted(
        p
        for p in REPO_ROOT.rglob("*.ps1")
        if not _is_excluded(p.relative_to(REPO_ROOT))
    )


def _discover_ps1_files() -> list[Path]:
    via_git = _discover_ps1_files_via_git()
    if via_git is not None:
        return via_git
    return _discover_ps1_files_via_walk()


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


def _git(*args: str, cwd: Path) -> None:
    """Run a plain, fixed-argv git command for test setup only."""
    subprocess.run(["git", *args], cwd=cwd, check=True)  # noqa: S603, S607 -- test setup only, no shell


def test_git_discovery_finds_untracked_but_not_gitignored_ps1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An uncommitted, never-``git add``ed ``.ps1`` is still discovered; an ignored one is not.

    This is the actual property ``--cached --others --exclude-standard``
    exists for: a file the author is actively writing must not get a free
    pass locally just because it has not been staged yet, while a file that
    is genuinely gitignored must stay excluded (that exclusion is unrelated
    to, and does not depend on, ``.claude/`` -- see the module's other test
    for the nested-worktree case, which is excluded by git's own repository
    boundary rather than by any ignore pattern).
    """
    _git("init", "-q", cwd=tmp_path)
    _git("config", "user.email", "t@example.com", cwd=tmp_path)
    _git("config", "user.name", "t", cwd=tmp_path)

    (tmp_path / ".gitignore").write_text("ignored.ps1\n", encoding="ascii")

    (tmp_path / "tracked.ps1").write_text("Write-Host 'tracked'\n", encoding="ascii")
    _git("add", "tracked.ps1", ".gitignore", cwd=tmp_path)

    (tmp_path / "untracked.ps1").write_text("Write-Host 'untracked'\n", encoding="ascii")
    (tmp_path / "ignored.ps1").write_text("Write-Host 'ignored'\n", encoding="ascii")

    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    result = _discover_ps1_files_via_git()
    assert result is not None, "git is available in this test environment"
    found = {p.name for p in result}

    assert "tracked.ps1" in found
    assert "untracked.ps1" in found
    assert "ignored.ps1" not in found


def test_no_discovered_ps1_file_is_inside_an_excluded_directory() -> None:
    """Discovery must never surface a file from a stale sibling worktree.

    A stale git worktree nested under ``.claude/worktrees/`` once doubled
    this test's parameter list with duplicate copies of
    ``installer/build.ps1`` and ``updater/build.ps1`` -- real files, but
    not part of this project's own tree. This checks the actual discovered
    set used for parametrisation, so it guards whichever discovery path
    ran (git or the filesystem-walk fallback) rather than one code path
    specifically.
    """
    for path in _PS1_FILES:
        rel_parts = path.relative_to(REPO_ROOT).parts
        offending = [part for part in rel_parts if part in _EXCLUDED_DIR_NAMES]
        assert not offending, (
            f"{path} is inside excluded directory {offending[0]!r} but was "
            "discovered anyway"
        )
