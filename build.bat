@echo off
REM Build both backends. Use build_openssl.bat or build_mbedtls.bat individually.

setlocal
echo === Building OpenSSL backend ===
call "%~dp0build_openssl.bat" || exit /b 1
echo.
echo === Building mbedTLS backend ===
call "%~dp0build_mbedtls.bat" || exit /b 1
echo.
echo === Both backends built successfully ===
endlocal
