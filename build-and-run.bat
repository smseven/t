@echo off
cd /d "%~dp0"
where cl >nul 2>nul
if %errorlevel%==0 (
  cl /std:c++17 /EHsc /O2 sharehub.cpp ws2_32.lib /Fe:sharehub.exe
) else (
  where g++ >nul 2>nul
  if errorlevel 1 (
    echo C++17 compiler not found. Use a Visual Studio Developer Command Prompt or install MinGW-w64.
    pause
    exit /b 1
  )
  g++ -std=c++17 -O2 sharehub.cpp -lws2_32 -o sharehub.exe
)
if errorlevel 1 (
  pause
  exit /b 1
)
sharehub.exe
