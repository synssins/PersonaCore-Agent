"""Guard the defect that shipped in 0.1.0-alpha.9: a bundled plugin whose
third-party dependency is not in the frozen bundle.

``workstation_agent.spec`` shipped every plugin's files as PyInstaller
``datas``.  Copying a file as data does not add it to PyInstaller's module
graph, so no plugin's imports were ever analysed and none of their
dependencies were collected.  ``plugins/serial/__main__.py`` does
``import serial`` at module scope, so the packaged app died with
``ModuleNotFoundError: No module named 'serial'`` the first time a
``serial.*`` tool was called.  ``plugins/devices`` had the same bug latent
(``from serial.tools import list_ports`` inside ``devices_list``).

**Why these tests cannot pass just because the venv happens to have
``pyserial`` installed.**  Nothing here imports a plugin, a plugin's
dependency, or PyInstaller.  The spec is read as text and executed with
``Analysis``/``PYZ``/``EXE``/``COLLECT`` and ``collect_submodules`` replaced
by recording stubs, and plugin sources are inspected with :mod:`ast`.  The
question asked is "does the spec carry the mechanism that makes PyInstaller
analyse this plugin?", which has the same answer on a machine with every
dependency installed and on a machine with none.  Run against the spec as it
was before the fix, every assertion below fails even though this venv has
``pyserial``.
"""
# ruff: noqa: S102, ANN401, ARG002
# S102: exec()ing the spec is the point — a PyInstaller spec IS a Python script.
# ANN401/ARG002: the stubs below stand in for PyInstaller's builder callables,
# whose signatures are (*args, **kwargs) by nature; most arguments are
# deliberately ignored.

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "workstation_agent.spec"
PLUGINS_DIR = REPO_ROOT / "src" / "workstation_agent" / "plugins"

PLUGIN_PKG = "workstation_agent.plugins"

#: The four files the spec ships for each plugin.
PLUGIN_FILES = ("plugin.toml", "signature.sig", "__main__.py", "__init__.py")

#: Import roots that are ours, not a third party's.
FIRST_PARTY_ROOTS = frozenset({"workstation_agent"})


# ---------------------------------------------------------------------------
# Executing the spec with stubs
# ---------------------------------------------------------------------------


class _SpecRun:
    """Records what a spec hands to PyInstaller's four builder callables."""

    def __init__(self) -> None:
        self.namespace: dict[str, Any] = {}
        self.analysis_kwargs: dict[str, Any] = {}
        self.pyz_toc: list[tuple[str, str, str]] = []

    # -- stubs ---------------------------------------------------------------

    def analysis(self, *args: Any, **kwargs: Any) -> Any:
        self.analysis_kwargs = kwargs

        fake = types.SimpleNamespace()
        # Model what PyInstaller actually does with hiddenimports: every named
        # module lands in the PYZ, and so does whatever it imports.  The two
        # ``serial`` entries stand in for the dependency closure the fix is
        # supposed to drag in; they are literals here, never an import.
        fake.pure = [
            (name, f"<{name}>", "PYMODULE") for name in kwargs.get("hiddenimports", [])
        ]
        fake.pure.append(("serial", "<serial>", "PYMODULE"))
        fake.pure.append(("serial.tools.list_ports", "<serial.tools.list_ports>", "PYMODULE"))
        fake.zipped_data = []
        fake.zipfiles = []
        fake.binaries = []
        fake.scripts = []
        fake.datas = list(kwargs.get("datas", []))
        return fake

    def pyz(self, toc: Any, *args: Any, **kwargs: Any) -> Any:
        self.pyz_toc = list(toc)
        return types.SimpleNamespace()

    def exe(self, *args: Any, **kwargs: Any) -> Any:
        return types.SimpleNamespace()

    def collect(self, *args: Any, **kwargs: Any) -> Any:
        return types.SimpleNamespace()


def _run_spec() -> _SpecRun:
    """Execute ``workstation_agent.spec`` with every PyInstaller call stubbed.

    ``PyInstaller.utils.hooks`` is stubbed too, so this runs identically in an
    environment where PyInstaller is not installed at all — which is what
    keeps the assertions independent of what the venv happens to contain.
    """
    run = _SpecRun()

    hooks = types.ModuleType("PyInstaller.utils.hooks")
    hooks.collect_submodules = lambda *_a, **_k: []  # type: ignore[attr-defined]
    utils = types.ModuleType("PyInstaller.utils")
    utils.hooks = hooks  # type: ignore[attr-defined]
    pyinstaller = types.ModuleType("PyInstaller")
    pyinstaller.utils = utils  # type: ignore[attr-defined]

    namespace: dict[str, Any] = {
        "__name__": "workstation_agent_spec",
        "__file__": str(SPEC_PATH),
        "__builtins__": __builtins__,
        # PyInstaller injects these into a spec's globals.
        "SPECPATH": str(REPO_ROOT),
        "DISTPATH": str(REPO_ROOT / "dist"),
        "WORKPATH": str(REPO_ROOT / "build"),
        "Analysis": run.analysis,
        "PYZ": run.pyz,
        "EXE": run.exe,
        "COLLECT": run.collect,
    }

    stubs = {
        "PyInstaller": pyinstaller,
        "PyInstaller.utils": utils,
        "PyInstaller.utils.hooks": hooks,
    }
    source = SPEC_PATH.read_text(encoding="utf-8")
    with mock.patch.dict(sys.modules, stubs):
        exec(compile(source, str(SPEC_PATH), "exec"), namespace)

    run.namespace = namespace
    return run


@pytest.fixture(scope="module")
def spec_run() -> _SpecRun:
    return _run_spec()


# ---------------------------------------------------------------------------
# Reading the plugin tree without importing any of it
# ---------------------------------------------------------------------------


def _bundled_plugin_dirs() -> list[Path]:
    """Every importable bundled plugin directory, from the filesystem."""
    return sorted(
        p
        for p in PLUGINS_DIR.iterdir()
        if p.is_dir() and not p.name.startswith("__") and (p / "__init__.py").exists()
    )


def _import_roots(path: Path) -> set[str]:
    """Root module names imported by *path*, at any nesting depth.

    Function-level and ``TYPE_CHECKING`` imports count: PyInstaller's module
    graph follows them too, and ``devices_list``'s ``from serial.tools import
    list_ports`` — a function-level import — is exactly the second instance of
    this bug.  Relative imports are skipped; they can only name siblings.
    """
    roots: set[str] = set()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _third_party_roots(plugin_dir: Path) -> set[str]:
    """Non-stdlib, non-first-party import roots used by *plugin_dir*.

    Classification is by name only — ``sys.stdlib_module_names`` is a frozen
    attribute of the interpreter, not of the environment — so this answers the
    same way whether or not the package is installed here.
    """
    roots: set[str] = set()
    for source in sorted(plugin_dir.rglob("*.py")):
        if "__pycache__" in source.parts:
            continue
        roots |= _import_roots(source)
    return {
        root
        for root in roots
        if root not in sys.stdlib_module_names
        and root not in FIRST_PARTY_ROOTS
        and not root.startswith("_")
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_plugin_tree_is_discoverable() -> None:
    """Sanity: the scan the other tests rely on actually finds plugins."""
    dirs = _bundled_plugin_dirs()
    assert dirs, f"no bundled plugins found under {PLUGINS_DIR}"


def test_every_bundled_plugin_is_analysed_by_the_spec(spec_run: _SpecRun) -> None:
    """Every plugin package + ``__main__`` must be in ``hiddenimports``.

    This is the mechanism that makes PyInstaller follow a plugin's imports and
    collect its dependencies.  Before the fix ``hiddenimports`` named no plugin
    at all, so this fails on the old spec regardless of what is installed.
    """
    hidden = set(spec_run.analysis_kwargs["hiddenimports"])

    expected: set[str] = set()
    for plugin_dir in _bundled_plugin_dirs():
        expected.add(f"{PLUGIN_PKG}.{plugin_dir.name}")
        if (plugin_dir / "__main__.py").exists():
            expected.add(f"{PLUGIN_PKG}.{plugin_dir.name}.__main__")

    missing = sorted(expected - hidden)
    assert not missing, (
        "these bundled plugin modules are not in workstation_agent.spec's "
        f"hiddenimports, so PyInstaller will never analyse them and their "
        f"dependencies will be missing from dist/Agent/: {missing}"
    )


def test_analysed_plugins_match_the_datas_scan(spec_run: _SpecRun) -> None:
    """The module list and the ``datas`` list come from one scan.

    That equality is what makes a plugin added tomorrow covered without
    touching the spec — the property this fix was asked for over hardcoding
    ``serial``.
    """
    assert "plugin_ids" in spec_run.namespace, (
        "workstation_agent.spec does not build a plugin_ids list, so nothing "
        "ties the modules it analyses to the plugin directories it ships"
    )
    analysed = set(spec_run.namespace["plugin_ids"])
    on_disk = {p.name for p in _bundled_plugin_dirs()}
    assert analysed == on_disk

    shipped = {
        dest.rsplit("/", 1)[-1]
        for _src, dest in spec_run.analysis_kwargs["datas"]
        if dest.startswith("workstation_agent/plugins/")
    }
    assert analysed == shipped


def test_every_plugin_ships_all_of_its_files(spec_run: _SpecRun) -> None:
    """The on-disk copy is what ``verify()`` hashes; it must be complete."""
    datas = spec_run.analysis_kwargs["datas"]
    shipped = {(Path(src).name, dest) for src, dest in datas}

    for plugin_dir in _bundled_plugin_dirs():
        dest = f"workstation_agent/plugins/{plugin_dir.name}"
        for name in PLUGIN_FILES:
            if (plugin_dir / name).exists():
                assert (name, dest) in shipped, (
                    f"{plugin_dir.name}/{name} exists in the source tree but is "
                    "not shipped as datas; the frozen plugin's signature covers "
                    "it and would fail to verify"
                )


def test_plugins_with_third_party_imports_are_covered(spec_run: _SpecRun) -> None:
    """A plugin that imports anything outside the stdlib must be analysed.

    This is the general form of the ``serial`` defect.  It is derived from the
    plugin sources with :mod:`ast`, so a plugin that grows a new dependency
    tomorrow is checked by the same rule and never needs a name added here.
    """
    hidden = set(spec_run.analysis_kwargs["hiddenimports"])

    offenders: list[str] = []
    for plugin_dir in _bundled_plugin_dirs():
        third_party = _third_party_roots(plugin_dir)
        if not third_party:
            continue
        module = f"{PLUGIN_PKG}.{plugin_dir.name}"
        if module not in hidden:
            offenders.append(f"{plugin_dir.name} imports {sorted(third_party)}")

    assert not offenders, (
        "these plugins import third-party packages but are not in the spec's "
        f"hiddenimports, so those packages will not be bundled: {offenders}"
    )


def test_serial_is_still_the_worked_example() -> None:
    """The reported crash, restated as an assertion about the source.

    If ``plugins/serial`` ever stops importing ``serial`` this test should be
    deleted, not weakened — but while it does, the rule above is load-bearing
    and this pins the case the field report actually hit.
    """
    assert "serial" in _third_party_roots(PLUGINS_DIR / "serial")
    assert "serial" in _third_party_roots(PLUGINS_DIR / "devices")


def test_bundled_plugins_are_kept_out_of_the_pyz(spec_run: _SpecRun) -> None:
    """Import and verification must resolve to the same, single copy.

    A hiddenimport also queues the module for the PYZ, and PyInstaller's
    frozen importer beats the filesystem path finder — so a PYZ copy would be
    executed while ``mcp_host.loader.verify`` went on hashing the on-disk copy
    the ``datas`` put in ``_internal/``.  Two copies that are compared to
    nothing is a signature bypass, so the spec strips the plugin modules back
    out of ``a.pure`` after Analysis.
    """
    pyz_names = {entry[0] for entry in spec_run.pyz_toc}
    leaked = sorted(
        name
        for name in pyz_names
        if name == PLUGIN_PKG or name.startswith(PLUGIN_PKG + ".")
    )
    assert not leaked, (
        "these plugin modules would be embedded in the PYZ and imported in "
        "preference to the on-disk copy that the Ed25519 signature covers, "
        f"letting the two diverge unnoticed: {leaked}"
    )


def test_plugin_dependencies_survive_the_pyz_strip(spec_run: _SpecRun) -> None:
    """Stripping the plugin modules must not strip what they dragged in."""
    pyz_names = {entry[0] for entry in spec_run.pyz_toc}
    assert "serial" in pyz_names
    assert "serial.tools.list_ports" in pyz_names
