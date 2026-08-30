# -*- mode: python ; coding: utf-8 -*-
# Cross-platform PyInstaller spec — builds a single-file ECDAT executable on
# Windows, macOS and Linux (each on its own OS via CI).
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [('app/static', 'app/static'), ('app/data', 'app/data')]
binaries = []
hiddenimports = ['app.server', 'app.ecdat']

for pkg in ['tree_sitter', 'tree_sitter_python', 'tree_sitter_javascript',
            'tree_sitter_java', 'uvicorn', 'h11', 'anyio']:
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h
for pkg in ['starlette', 'fastapi']:
    hiddenimports += collect_submodules(pkg)

a = Analysis(['run_ecdat.py'], pathex=[], binaries=binaries, datas=datas,
             hiddenimports=hiddenimports, hookspath=[], runtime_hooks=[],
             excludes=['uvloop', 'httptools', 'watchfiles'], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name='ECDAT',
          debug=False, strip=False, upx=False, console=True,
          disable_windowed_traceback=False, target_arch=None)
