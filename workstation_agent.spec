# -*- mode: python -*-
# PyInstaller spec for PersonaCore-Agent — one-folder Windows build.
#
# Produces ``dist/Agent/Agent.exe`` alongside every data file the app
# needs at runtime: UI backend templates + static files, systray assets,
# and every first-party plugin's manifest + signature + code — plus, since
# 0.1.0-alpha.9's ``No module named 'serial'``, the third-party packages
# those plugins import (see the plugin section below).
#
# Build with:
#
#     .venv/Scripts/python.exe -m PyInstaller workstation_agent.spec
#
# The output lives in ``dist/Agent/`` and is what Inno Setup ships.

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

REPO_ROOT = Path(SPECPATH)  # noqa: F821 — provided by PyInstaller
SRC = REPO_ROOT / "src" / "workstation_agent"

datas = [
    (str(SRC / "ui" / "backend" / "templates"), "workstation_agent/ui/backend/templates"),
    (str(SRC / "ui" / "backend" / "static"), "workstation_agent/ui/backend/static"),
    (str(SRC / "ui" / "systray" / "assets"), "workstation_agent/ui/systray/assets"),
]

# ---------------------------------------------------------------------------
# Bundled first-party plugins.
#
# Three things have to be true for a bundled plugin to work in the frozen
# app.  Until 0.1.0-alpha.9 only the first was, and the second was the defect
# a real install hit:
#
#   1. The plugin's files must exist ON DISK under
#      ``_internal/workstation_agent/plugins/<id>/``.  That on-disk copy is
#      what the Ed25519 signature is checked against: ``mcp_host.loader``'s
#      ``signing_message`` -> ``_covered_files`` resolves the manifest's
#      ``entry = ["-m", "workstation_agent.plugins.<id>"]`` with
#      ``importlib.util.find_spec`` and hashes every importable file under
#      ``spec.submodule_search_locations``.  Shipping the four files as
#      ``datas`` is what puts them there, and that part always worked.
#
#   2. The plugin's DEPENDENCIES must be in the bundle.  Copying a file as
#      data does not add it to PyInstaller's module graph, so no bundled
#      plugin's imports were ever analysed and their third-party packages
#      were simply absent from ``dist/Agent/_internal``.  ``serial`` was the
#      first family to notice, because it is the first one that imports
#      something outside the standard library at module scope:
#      ``ModuleNotFoundError: No module named 'serial'`` from
#      ``plugins/serial/__main__.py`` on the owner's machine.  ``devices``
#      carried the same latent bug (``devices_list`` reaches for
#      ``serial.tools.list_ports`` inside a function).  The fix is to name
#      each plugin's modules in ``hiddenimports`` below, so Analysis walks
#      them and drags in whatever they import — driven off the SAME
#      directory scan as the ``datas`` loop, so the next family to grow a
#      dependency is covered without editing this file.
#
#   3. The copy that is IMPORTED must be the copy that is VERIFIED.  A
#      hiddenimport also lands the module itself in the PYZ, and
#      PyInstaller's frozen importer sits ahead of the filesystem path
#      finder on ``sys.meta_path`` — so the PYZ copy would win every import
#      while ``verify()`` went on hashing the on-disk copy.  The two could
#      then be edited apart: arbitrary code executing under a ``valid``
#      signature.  So after Analysis every ``workstation_agent.plugins.*``
#      module is stripped back out of ``a.pure`` (see below).  Their
#      dependencies, collected by then, stay.
#
# Net effect: the PYZ's ``workstation_agent.plugins`` namespace is byte-for-
# byte what it was before this change (empty), the on-disk tree is what it
# was before, and only the dependency closure grew.
# ---------------------------------------------------------------------------

PLUGIN_PKG = "workstation_agent.plugins"

#: Directory names under ``src/workstation_agent/plugins/`` that are plugins.
plugin_ids: list[str] = []
#: Module names handed to Analysis so each plugin's imports get followed.
plugin_modules: list[str] = []

for plugin_dir in sorted((SRC / "plugins").iterdir()):
    if not plugin_dir.is_dir():
        continue
    if plugin_dir.name.startswith("__"):
        continue
    dest = f"workstation_agent/plugins/{plugin_dir.name}"
    for name in ("plugin.toml", "signature.sig", "__main__.py", "__init__.py"):
        src_file = plugin_dir / name
        if src_file.exists():
            datas.append((str(src_file), dest))

    # Only a directory with an ``__init__.py`` is an importable package, and
    # only ``__main__.py`` is what ``-m <package>`` actually executes — the
    # module that hit the ModuleNotFoundError.  Both are named explicitly:
    # nothing in the app imports either statically, so neither would be
    # reached by following imports from the entry script.
    if not (plugin_dir / "__init__.py").exists():
        continue
    plugin_ids.append(plugin_dir.name)
    plugin_modules.append(f"{PLUGIN_PKG}.{plugin_dir.name}")
    if (plugin_dir / "__main__.py").exists():
        plugin_modules.append(f"{PLUGIN_PKG}.{plugin_dir.name}.__main__")

print(  # noqa: T201 — build-log evidence that the scan found every plugin
    f"workstation_agent.spec: analysing {len(plugin_ids)} bundled plugin(s) "
    f"for their dependencies: {', '.join(plugin_ids)}",
)

hiddenimports = [
    "workstation_agent",
    "workstation_agent.__main__",
    "workstation_agent.app",
    "workstation_agent.ui.backend.routers.dashboard",
    "workstation_agent.ui.backend.routers.first_run",
    "workstation_agent.ui.backend.routers.config_routes",
    "workstation_agent.ui.backend.routers.plugins_routes",
    "workstation_agent.ui.backend.routers.network_mcp_routes",
    "workstation_agent.ui.backend.credential_reveal",
    "workstation_agent.ui.backend.routers.audit_routes",
    "workstation_agent.ui.backend.routers.logs_routes",
    "workstation_agent.ui.backend.routers.about_routes",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    # B4's network MCP endpoint (src/workstation_agent/network_mcp/server.py)
    # imports these lazily, inside functions, so a build off a machine where
    # they were never imported at module scope during analysis can miss
    # them. Declared explicitly rather than hoped for.
    "workstation_agent.network_mcp",
    "workstation_agent.network_mcp.server",
    "workstation_agent.network_mcp.tools",
    "workstation_agent.network_mcp.certs",
    "workstation_agent.network_mcp.credentials",
    "workstation_agent.network_mcp.hardening",
    "workstation_agent.registration_export",
    "mcp",
    "mcp.server",
    "mcp.server.lowlevel",
    "mcp.server.streamable_http",
    "mcp.server.streamable_http_manager",
    "mcp.server.transport_security",
    "mcp.types",
    "sse_starlette",
    "sse_starlette.sse",
    # Bundled plugins — see the long comment above the plugin scan.  These are
    # here ONLY so Analysis follows their imports; the modules themselves are
    # removed from the PYZ again after Analysis so the on-disk, signature-
    # covered copy stays the only importable one.
    *plugin_modules,
]

block_cipher = None

# We ship webrtcvad via the `webrtcvad-wheels` distribution (prebuilt wheels).
# pyinstaller-hooks-contrib ships a stock `hook-webrtcvad.py` that looks up
# the ORIGINAL `webrtcvad` distribution metadata and crashes with
# `PackageNotFoundError` under -wheels. The module itself imports fine —
# `hiddenimports=["webrtcvad"]` plus disabling the hook is the tidy fix.
hiddenimports.append("webrtcvad")

# ---------------------------------------------------------------------------
# winrt (subtask P5) — toast.py's real notification backend.
#
# The `winrt` distribution ships each `Windows.*` namespace as its own PyPI
# package (winrt-runtime, winrt-Windows.UI.Notifications,
# winrt-Windows.Data.Xml.Dom, winrt-Windows.Foundation — see pyproject.toml
# for why all four are required) but they all install INTO ONE SHARED,
# `winrt` PEP 420 *implicit namespace package* with no `__init__.py` at
# `winrt/`, `winrt/windows/`, `winrt/windows/data/` or `winrt/windows/ui/` —
# only the leaf packages (`winrt.windows.data.xml.dom`,
# `winrt.windows.foundation`, `winrt.windows.ui.notifications`) carry a real
# `__init__.py`. Verified by hand:
# `PyInstaller.utils.hooks.collect_submodules("winrt")` cannot walk PAST
# those intermediate namespace levels (it returns the top-level native
# extension modules and `winrt.runtime`/`winrt.system`, but never discovers
# `winrt.windows`, `winrt.windows.ui`, `winrt.windows.ui.notifications`,
# `winrt.windows.data`, `winrt.windows.data.xml`,
# `winrt.windows.data.xml.dom` or `winrt.windows.foundation`) — so those
# namespace/leaf packages are listed explicitly below rather than trusted to
# the automatic sweep. Each leaf package's real `__init__.py` then imports
# its backing native extension by name (e.g.
# `from winrt._winrt_windows_ui_notifications import ...`); PyInstaller's
# own import-following picks up the matching `.pyd` binaries once it can
# actually reach and scan those leaf `__init__.py` files, which requires the
# namespace levels above to be declared too.
hiddenimports.extend(collect_submodules("winrt"))
hiddenimports.extend(
    [
        "winrt.windows",
        "winrt.windows.data",
        "winrt.windows.data.xml",
        "winrt.windows.data.xml.dom",
        "winrt.windows.foundation",
        "winrt.windows.ui",
        "winrt.windows.ui.notifications",
    ],
)

a = Analysis(  # noqa: F821
    [str(SRC / "__main__.py")],
    pathex=[str(REPO_ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["_pyinstaller_hooks_contrib.stdhooks.hook-webrtcvad"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)


# ---------------------------------------------------------------------------
# Keep the bundled plugins OUT of the PYZ (requirement 3 above).
#
# ``hiddenimports`` got Analysis to follow every plugin's imports, which is
# the whole point — ``pyserial`` and friends are now in the bundle.  But it
# also queued the plugin modules themselves for the PYZ, and a PYZ copy would
# be imported in preference to the on-disk copy that ``mcp_host.loader``
# hashes.  Dropping them here leaves exactly one copy of every plugin in the
# shipped app: ``_internal/workstation_agent/plugins/<id>/*.py``, which is
# both the copy ``runpy.run_module`` executes and the copy ``verify()``
# digests.  They cannot diverge, because there is nothing to diverge from.
#
# Only the plugin modules are dropped.  Everything they pulled in — ``serial``,
# ``serial.tools.list_ports``, ``serial.serialwin32`` … — is an ordinary
# third-party module elsewhere in ``a.pure`` and stays.
# ---------------------------------------------------------------------------


def _is_bundled_plugin_module(module_name: str) -> bool:
    """True for ``workstation_agent.plugins`` and anything beneath it."""
    return module_name == PLUGIN_PKG or module_name.startswith(PLUGIN_PKG + ".")


_kept_pure = [entry for entry in a.pure if not _is_bundled_plugin_module(entry[0])]
_dropped_pure = sorted(entry[0] for entry in a.pure if _is_bundled_plugin_module(entry[0]))
a.pure.clear()
a.pure.extend(_kept_pure)

print(  # noqa: T201 — build-log evidence that the strip actually happened
    f"workstation_agent.spec: kept {len(_dropped_pure)} plugin module(s) out of "
    f"the PYZ so the on-disk signed copy is the only importable one: "
    f"{', '.join(_dropped_pure)}",
)

# A plugin whose files never made it into ``datas`` would be stripped from the
# PYZ and absent from disk — i.e. silently unshippable.  Fail the build rather
# than ship that.
_shipped_dests = {dest for _src, dest in datas}
_missing_on_disk = [
    plugin_id
    for plugin_id in plugin_ids
    if f"workstation_agent/plugins/{plugin_id}" not in _shipped_dests
]
if _missing_on_disk:
    msg = (
        "bundled plugins removed from the PYZ but not shipped as datas — "
        f"they would be missing from the frozen app entirely: {_missing_on_disk}"
    )
    raise RuntimeError(msg)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Agent",
)
