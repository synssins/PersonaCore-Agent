# -*- mode: python -*-
# PyInstaller spec for PersonaCore-Agent — one-folder Windows build.
#
# Produces ``dist/Agent/Agent.exe`` alongside every data file the app
# needs at runtime: UI backend templates + static files, systray assets,
# and all six first-party plugin manifests + signatures.
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

# Bundled first-party plugins — ship manifest + signature + __main__.py for
# every plugin under src/workstation_agent/plugins/.
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
