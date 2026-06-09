@echo off
REM Build the OpenSSL backend: ecc_demo_openssl.exe + vendored DLLs.
REM Requires a MinGW-w64 g++ (msys2/mingw64 by default).

setlocal

if "%MINGW_DIR%"=="" set MINGW_DIR=C:\msys64\mingw64
set OPENSSL_DIR=%~dp0third_party\openssl
set PATH=%MINGW_DIR%\bin;%PATH%

where g++ >nul 2>&1
if errorlevel 1 (
    echo ERROR: g++ not found. Set MINGW_DIR to your MinGW-w64 install root.
    exit /b 1
)

echo Building ecc_demo_openssl.exe ^(dynamic link, OpenSSL from %OPENSSL_DIR%^)...
g++ -std=c++11 -O2 -Wall -Wno-deprecated-declarations ^
    -static-libgcc -static-libstdc++ ^
    -I"%OPENSSL_DIR%\include" ^
    CEccModule_openssl.cpp main.cpp ^
    -L"%OPENSSL_DIR%\lib" -lcrypto ^
    -lws2_32 -lcrypt32 ^
    -o ecc_demo_openssl.exe
if errorlevel 1 (
    echo BUILD FAILED.
    exit /b 1
)

copy /Y "%OPENSSL_DIR%\bin\libcrypto-3-x64.dll" . >nul
copy /Y "%OPENSSL_DIR%\bin\libwinpthread-1.dll" . >nul
echo Built ecc_demo_openssl.exe + libcrypto-3-x64.dll + libwinpthread-1.dll.
endlocal
