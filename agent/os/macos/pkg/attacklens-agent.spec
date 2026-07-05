# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['agent/agent_entry.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['agent.agent.collectors', 'agent.agent.normalizer', 'agent.agent.enrollment', 'agent.agent.keystore', 'tomllib'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='attacklens-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch='arm64',
    codesign_identity=None,
    entitlements_file=None,
)
