@echo off
rem Builds the portable single-file executable: dist\RamCapper.exe
setlocal
cd /d "%~dp0"
python -m pip install --upgrade -r requirements.txt pyinstaller || goto :fail
python tools\make_version.py || goto :fail
python -m PyInstaller --noconfirm --clean --onefile --noconsole --noupx --icon assets\ramcapper.ico --version-file assets\version_info.txt --name RamCapper --add-data "web;web" --add-data "assets\oui.json.gz;assets" ramcapper.py || goto :fail
echo.
echo Built: %~dp0dist\RamCapper.exe
exit /b 0
:fail
echo Build failed.
exit /b 1
