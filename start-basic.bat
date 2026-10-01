@echo off
cd /d "%~dp0"
if not exist build\sharehub.exe (
  echo Build sharehub.exe with build-and-run.bat first.
  pause
  exit /b 1
)
echo Basic mode: pairing codes and files are not encrypted.
build\sharehub.exe --mode basic %*
pause
