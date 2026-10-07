@echo off
setlocal EnableExtensions

set "PROJECT_ROOT=%~dp0"
if defined VSDEV goto :configure_toolchain

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDEV=%%I\Common7\Tools\VsDevCmd.bat"
)
if defined VSDEV goto :configure_toolchain

rem Fallback for default installation paths when vswhere is unavailable.
for %%V in (18 2022 2019) do (
  for %%E in (Community Professional Enterprise BuildTools) do (
    if not defined VSDEV if exist "%ProgramFiles%\Microsoft Visual Studio\%%V\%%E\Common7\Tools\VsDevCmd.bat" set "VSDEV=%ProgramFiles%\Microsoft Visual Studio\%%V\%%E\Common7\Tools\VsDevCmd.bat"
  )
)
if not defined VSDEV (
  echo Visual Studio C++ build tools were not found.
  echo Install Desktop development with C++, or set VSDEV to VsDevCmd.bat.
  exit /b 1
)

:configure_toolchain
if not exist "%VSDEV%" (
  echo VsDevCmd.bat was not found at: %VSDEV%
  exit /b 1
)
call "%VSDEV%" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1

if not exist "%PROJECT_ROOT%build" mkdir "%PROJECT_ROOT%build"
if not exist "%PROJECT_ROOT%dist" mkdir "%PROJECT_ROOT%dist"

pushd "%PROJECT_ROOT%src"
rc /nologo /fo "..\build\MioCrypt.res" MioCrypt.rc
if errorlevel 1 goto :build_failed

cl /nologo /utf-8 /W4 /Zi /Fd"..\build\MioCrypt-compile.pdb" /Od /Ob0 /MT /DUNICODE /D_UNICODE ^
  /Fo"..\build\\" /Tcmiocrypt.c "..\build\MioCrypt.res" ^
  /link /DEBUG:FULL /OPT:NOREF /OPT:NOICF /INCREMENTAL:NO /PDB:"..\build\MioCrypt.pdb" ^
  /SUBSYSTEM:WINDOWS /OUT:"..\build\MioCrypt.exe" bcrypt.lib user32.lib gdi32.lib
if errorlevel 1 goto :build_failed
popd

copy /y "%PROJECT_ROOT%build\MioCrypt.exe" "%PROJECT_ROOT%dist\MioCrypt.exe" >nul
if errorlevel 1 exit /b 1
copy /y "%PROJECT_ROOT%build\MioCrypt.pdb" "%PROJECT_ROOT%dist\MioCrypt.pdb" >nul
if errorlevel 1 exit /b 1
echo Build complete: %PROJECT_ROOT%dist\MioCrypt.exe
exit /b 0

:build_failed
popd
echo Build failed.
exit /b 1
