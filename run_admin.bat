@echo off
rem Starts RamCapper elevated so it can trim/cap/end elevated and system processes too.
cd /d "%~dp0"
powershell -NoProfile -Command "Start-Process pythonw -ArgumentList 'ramcapper.py' -WorkingDirectory '%~dp0' -Verb RunAs"
