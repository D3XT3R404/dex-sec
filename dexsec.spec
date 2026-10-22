# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for DEX-SEC — build a single file executable.

    pyinstaller dexsec.spec

Result: dist/dexsec.exe (Windows) or dist/dexsec (Linux/macOS)
"""

block_cipher = None

a = Analysis(
    ["run_dexsec.py"],
    pathex=["."],
    binaries=[],
    datas=[("dexsec/manual", "dexsec/manual")],
    hiddenimports=[
        "rich",
        "rich.console",
        "rich.panel",
        "rich.syntax",
        "rich.table",
        "rich.progress",
        "requests",
        "typer",
        "click",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "IPython",
        "pytest",
        "selenium",
        "cv2",
        "PIL",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="dexsec",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
