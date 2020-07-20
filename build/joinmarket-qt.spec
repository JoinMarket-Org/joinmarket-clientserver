# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

# several tricks copied from Electrum wine build:
# https://github.com/spesmilo/electrum/blob/aa1fb9d5df4eda7ce0923775af1ef8ff79c67b97/contrib/build-wine/deterministic.spec

block_cipher = None

binaries = []

# Workaround for "Retro Look":
#binaries += [b for b in collect_dynamic_libs('PyQt5') if 'qwindowsvista' in b[0]]
binaries += [('C:/tmp/libsecp256k1-0.dll', '.')]
binaries += [('C:/tmp/libsodium.dll','.')]
binaries += collect_dynamic_libs('coincurve')

datas = []
datas += collect_data_files('mnemonic')
hiddenimports=['chromalog.mark.helpers', 'PySide2']
# see https://github.com/pypa/setuptools/issues/1963
hiddenimports.extend(collect_submodules('pkg_resources'))

a = Analysis(['../scripts/joinmarket-qt.py'],
             binaries=binaries,
             datas=datas,
             hiddenimports=hiddenimports,
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
             
# Strip out parts of Qt that we never use. Reduces binary size by tens of MBs. see #4815
qt_bins2remove=('qt5web', 'qt53d', 'qt5game', 'qt5designer', 'qt5quick',
                'qt5location', 'qt5test', 'qt5xml', r'pyqt5\qt\qml\qtquick')
print("Removing Qt binaries:", *qt_bins2remove)
for x in a.binaries.copy():
    for r in qt_bins2remove:
        if x[0].lower().startswith(r):
            a.binaries.remove(x)
            print('----> Removed x =', x)

qt_data2remove=(r'pyqt5\qt\translations\qtwebengine_locales', )
print("Removing Qt datas:", *qt_data2remove)
for x in a.datas.copy():
    for r in qt_data2remove:
        if x[0].lower().startswith(r):
            a.datas.remove(x)
            print('----> Removed x =', x)

# https://github.com/spesmilo/electrum/pull/3185
a.binaries = [x for x in a.binaries if not x[1].lower().startswith(r'c:\windows')]

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='joinmarket-qt',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=False ) #note console=True is useful for debugging errors

