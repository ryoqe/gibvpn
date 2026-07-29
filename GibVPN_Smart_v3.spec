# -*- mode: python ; coding: utf-8 -*-

import os
import glob

work_dir = os.path.abspath(SPECPATH)

# Files that must be shipped next to the .exe so xray can find them at runtime.
helper_files = [
    'xray.exe',
    'geoip.dat',
    'geosite.dat',
    'direct_domains.txt',
    'direct_apps.txt',
    'warp_domains.txt',
    'wgcf-account.toml',
    'wgcf-profile.conf',
    'ofont.ru_Zeequada.ttf',
    'app_settings.json',
]

# Files that live in the project directory and are copied as data files.
# decoded_sub*.txt are user-specific cache files and should not be bundled.
datas = [(os.path.join(work_dir, f), '.') for f in helper_files if os.path.exists(os.path.join(work_dir, f))]

if os.path.exists(os.path.join(work_dir, 'zapret_bin')):
    datas.append((os.path.join(work_dir, 'zapret_bin'), 'zapret_bin'))

if os.path.exists(os.path.join(work_dir, 'singbox_bin')):
    datas.append((os.path.join(work_dir, 'singbox_bin'), 'singbox_bin'))

if os.path.exists(os.path.join(work_dir, 'assets')):
    datas.append((os.path.join(work_dir, 'assets'), 'assets'))

a = Analysis(
    ['gui.py'],
    pathex=[work_dir],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'PyQt6.sip',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'requests',
        'urllib3',
        'charset_normalizer',
        'idna',
        'certifi',
    ],
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
    [],
    exclude_binaries=True,
    name='GibVPN_Smart_v3',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=os.path.join(work_dir, 'version.txt'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='GibVPN_Smart_v3',
)
