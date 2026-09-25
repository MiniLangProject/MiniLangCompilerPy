# Build the Windows x64 std.video bridge with the installed Windows SDK.
[CmdletBinding()]
param([string]$OutputDir = "$PSScriptRoot/../../../build/native/video/windows-x64")

$ErrorActionPreference = "Stop"
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$vswhere = "${env:ProgramFiles(x86)}/Microsoft Visual Studio/Installer/vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere)) {
  throw "Visual Studio C++ x64 build tools are required."
}
$vs = & $vswhere -latest -products "*" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) {
  # An installation awaiting a reboot may not advertise every component even
  # though its command-line toolchain is usable.
  $vs = & $vswhere -all -products "*" -property installationPath | Select-Object -First 1
}
if (-not $vs) { throw "Visual Studio C++ x64 build tools are required." }

$devcmd = Join-Path $vs "Common7/Tools/VsDevCmd.bat"
$source = Join-Path $PSScriptRoot "minilang_video.cpp"
$include = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../include"))
$compileCmd = Join-Path $OutputDir "compile.cmd"
@"
@echo off
call "$devcmd" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /MT /O2 /W4 /LD /I"$include" "$source" /Fo"$OutputDir/minilang_video.obj" /link /IMPLIB:"$OutputDir/minilang_video.lib" /OUT:"$OutputDir/minilang_video.dll" mfplat.lib mfuuid.lib ole32.lib oleaut32.lib shlwapi.lib user32.lib winmm.lib
"@ | Set-Content -LiteralPath $compileCmd -Encoding ascii
& $env:ComSpec /d /c $compileCmd
if ($LASTEXITCODE -ne 0) { throw "std.video Windows bridge build failed." }
Write-Host "Wrote: $OutputDir/minilang_video.dll"
