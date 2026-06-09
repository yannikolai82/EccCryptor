@echo off
REM Build the mbedTLS backend: ecc_demo_mbedtls.exe.
REM Self-contained binary: no runtime DLL dependency on libcrypto.
REM Requires a MinGW-w64 toolchain (gcc + g++).

setlocal

if "%MINGW_DIR%"=="" set MINGW_DIR=C:\msys64\mingw64
set MBED_DIR=%~dp0third_party\mbedtls
set PATH=%MINGW_DIR%\bin;%PATH%
set OBJDIR=%~dp0build_mbedtls_obj

where g++ >nul 2>&1
if errorlevel 1 (
    echo ERROR: g++ not found. Set MINGW_DIR to your MinGW-w64 install root.
    exit /b 1
)

if not exist "%OBJDIR%" mkdir "%OBJDIR%"

REM 19 mbedTLS source files (the rest are disabled by config.h and would be no-ops).
set MBED_SRC=aes asn1parse asn1write bignum cipher cipher_wrap constant_time ecdh ecdsa ecp ecp_curves error gcm hkdf md oid platform platform_util sha256

set MBED_OBJS=
echo Compiling mbedTLS sources...
for %%F in (%MBED_SRC%) do (
    gcc -c -std=c99 -O2 -Wall ^
        -I"%MBED_DIR%\include" ^
        -D_WIN32_WINNT=0x0501 ^
        "%MBED_DIR%\library\%%F.c" ^
        -o "%OBJDIR%\%%F.o"
    if errorlevel 1 (
        echo BUILD FAILED on %%F.c
        exit /b 1
    )
    call set MBED_OBJS=%%MBED_OBJS%% "%OBJDIR%\%%F.o"
)

echo Linking ecc_demo_mbedtls.exe...
g++ -std=c++11 -O2 -Wall ^
    -static ^
    -I"%MBED_DIR%\include" ^
    -D_WIN32_WINNT=0x0501 ^
    CEccModule_mbedtls.cpp main.cpp ^
    %MBED_OBJS% ^
    -ladvapi32 ^
    -o ecc_demo_mbedtls.exe
if errorlevel 1 (
    echo LINK FAILED.
    exit /b 1
)

echo Built ecc_demo_mbedtls.exe ^(self-contained, no DLLs required^).
endlocal
