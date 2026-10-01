@echo off
cd /d "%~dp0"
where cl >nul 2>nul
if %errorlevel%==0 (
  cl /std:c++17 /utf-8 /EHsc /O2 /MT sharehub.cpp ws2_32.lib bcrypt.lib secur32.lib crypt32.lib shell32.lib /Fe:sharehub.exe
) else (
  where g++ >nul 2>nul
  if errorlevel 1 (
    echo C++17 compiler not found. Use a Visual Studio Developer Command Prompt or install MinGW-w64.
    pause
    exit /b 1
  )
  g++ -std=c++17 -O2 -Wall -Wextra sharehub.cpp -lws2_32 -lbcrypt -lsecur32 -lcrypt32 -lshell32 -o sharehub.exe
)
if errorlevel 1 (
  pause
  exit /b 1
)
if not "%~1"=="" (
  sharehub.exe %*
  exit /b
)
echo 1. Secure mode - HTTPS certificate required
echo 2. Basic mode - HTTP without encryption
set /p "sharehub_mode=Select mode [1]: "
if "%sharehub_mode%"=="2" (
  sharehub.exe --mode basic
) else (
  sharehub.exe --mode secure
)
pause
