@echo off
rem Stops RamCapper. If it was started as administrator, this asks for elevation to close it.
set "PS=powershell -NoProfile -Command"
set "FIND=Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'ramcapper\.py' -or $_.Name -eq 'RamCapper.exe' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
%PS% "%FIND%"
timeout /t 1 /nobreak >nul
%PS% "if (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue) { exit 1 }"
if errorlevel 1 (
  echo RamCapper is running elevated - requesting administrator rights to close it...
  %PS% "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-Command','Get-NetTCPConnection -LocalPort 8765 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }'"
)
%PS% "if (Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue) { 'RamCapper is still running.' } else { 'RamCapper stopped.' }"
timeout /t 2 >nul
