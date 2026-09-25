<#
Build and exercise std.video through both compiler implementations and targets.
FFmpeg supplies only a deterministic test fixture; it is not a runtime
dependency of std.video.
#>
[CmdletBinding()]
param(
  [string]$Python = "python",
  [string]$PythonCompiler = "",
  [string]$SelfHostedCompiler = "",
  [string]$WslDistribution = "Ubuntu",
  [switch]$SkipLinux
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$Source = Join-Path $Root "tests/video_stdlib.ml"
$Artifacts = Join-Path $Root "build/native/video"
$WindowsArtifacts = Join-Path $Artifacts "windows-x64"
$LinuxArtifacts = Join-Path $Artifacts "linux-x64"
New-Item -ItemType Directory -Force -Path $WindowsArtifacts, $LinuxArtifacts | Out-Null

if ([string]::IsNullOrWhiteSpace($PythonCompiler)) {
  $candidates = @(
    (Join-Path $Root "mlc_win64.py"),
    (Join-Path $Root "../MiniLangCompilerPy/mlc_win64.py")
  )
  $PythonCompiler = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $PythonCompiler -or -not (Test-Path -LiteralPath $PythonCompiler)) {
  throw "MiniLang Python compiler was not found; pass -PythonCompiler."
}
$PythonCompiler = [IO.Path]::GetFullPath($PythonCompiler)

if ([string]::IsNullOrWhiteSpace($SelfHostedCompiler)) {
  $candidates = @(
    (Join-Path $Root "build/mlc_win64.exe"),
    (Join-Path $Root "../MiniLangCompilerML/build/mlc_win64.exe")
  )
  $SelfHostedCompiler = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $SelfHostedCompiler -or -not (Test-Path -LiteralPath $SelfHostedCompiler)) {
  throw "Self-hosted MiniLang compiler was not found; pass -SelfHostedCompiler."
}
$SelfHostedCompiler = [IO.Path]::GetFullPath($SelfHostedCompiler)

$ffmpeg = (Get-Command ffmpeg -ErrorAction Stop).Source
$Fixture = Join-Path $Artifacts "video-fixture.avi"
$AudioFixture = Join-Path $Artifacts "video-audio-fixture.avi"
& $ffmpeg -hide_banner -loglevel error -f lavfi -i "testsrc=size=160x90:rate=30" -t 2 -an -c:v rawvideo -pix_fmt yuv420p -threads 1 -y $Fixture
if ($LASTEXITCODE -ne 0) { throw "FFmpeg fixture generation failed." }
& $ffmpeg -hide_banner -loglevel error -f lavfi -i "testsrc=size=160x90:rate=30" -f lavfi -i "sine=frequency=440:sample_rate=48000" -t 2 -c:v rawvideo -pix_fmt yuv420p -c:a pcm_s16le -threads 1 -y $AudioFixture
if ($LASTEXITCODE -ne 0) { throw "FFmpeg audio fixture generation failed." }

& (Join-Path $PSScriptRoot "windows/build.ps1") -OutputDir $WindowsArtifacts
if ($LASTEXITCODE -ne 0) { throw "Windows video bridge build failed." }

$PythonWindows = Join-Path $WindowsArtifacts "video-python.exe"
$SelfHostedWindows = Join-Path $WindowsArtifacts "video-selfhosted.exe"
& $Python $PythonCompiler $Source $PythonWindows -I $Root --target windows-x64
if ($LASTEXITCODE -ne 0) { throw "Python compiler Windows build failed." }
& $PythonWindows $Fixture $AudioFixture
if ($LASTEXITCODE -ne 0) { throw "Python compiler Windows playback test failed." }
& $SelfHostedCompiler $Source $SelfHostedWindows -I $Root --target windows-x64
if ($LASTEXITCODE -ne 0) { throw "Self-hosted Windows build failed." }
& $SelfHostedWindows $Fixture $AudioFixture
if ($LASTEXITCODE -ne 0) { throw "Self-hosted Windows playback test failed." }

$ParityWindows = Join-Path $WindowsArtifacts "video-parity.exe"
& $Python $PythonCompiler $Source $ParityWindows -I $Root --target windows-x64 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Python compiler Windows parity build failed." }
$PythonWindowsHash = (Get-FileHash $ParityWindows -Algorithm SHA256).Hash
& $SelfHostedCompiler $Source $ParityWindows -I $Root --target windows-x64 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Self-hosted Windows parity build failed." }
$SelfHostedWindowsHash = (Get-FileHash $ParityWindows -Algorithm SHA256).Hash
if ($PythonWindowsHash -ne $SelfHostedWindowsHash) {
  throw "Windows compiler output differs: $PythonWindowsHash != $SelfHostedWindowsHash"
}
& $SelfHostedCompiler $Source $ParityWindows -I $Root --target windows-x64 --object-pipeline | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Self-hosted Windows object-pipeline build failed." }
$ObjectWindowsHash = (Get-FileHash $ParityWindows -Algorithm SHA256).Hash
if ($PythonWindowsHash -ne $ObjectWindowsHash) {
  throw "Windows object-pipeline output differs: $PythonWindowsHash != $ObjectWindowsHash"
}

if (-not $SkipLinux) {
  if ($Root.Contains("'")) { throw "Repository path may not contain a single quote." }
  $WslRoot = (& wsl.exe -d $WslDistribution -- bash -lc "wslpath -a '$Root'").Trim()
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($WslRoot)) {
    throw "Could not map the repository into WSL; use -SkipLinux if unavailable."
  }
  if ($WslRoot.Contains("'")) { throw "WSL repository path may not contain a single quote." }
  & wsl.exe -d $WslDistribution -- bash -lc "cd '$WslRoot' && sh native/video/linux/build.sh"
  if ($LASTEXITCODE -ne 0) { throw "Linux video bridge build failed." }

  $PythonLinux = Join-Path $LinuxArtifacts "video-python"
  $SelfHostedLinux = Join-Path $LinuxArtifacts "video-selfhosted"
  & $Python $PythonCompiler $Source $PythonLinux -I $Root --target linux-x64
  if ($LASTEXITCODE -ne 0) { throw "Python compiler Linux build failed." }
  & $SelfHostedCompiler $Source $SelfHostedLinux -I $Root --target linux-x64
  if ($LASTEXITCODE -ne 0) { throw "Self-hosted Linux build failed." }

  $WslArtifacts = "$WslRoot/build/native/video"
  & wsl.exe -d $WslDistribution -- bash -lc "cd '$WslArtifacts/linux-x64' && chmod +x video-python video-selfhosted && ./video-python ../video-fixture.avi ../video-audio-fixture.avi && ./video-selfhosted ../video-fixture.avi ../video-audio-fixture.avi"
  if ($LASTEXITCODE -ne 0) { throw "Linux playback test failed." }

  $ParityLinux = Join-Path $LinuxArtifacts "video-parity"
  & $Python $PythonCompiler $Source $ParityLinux -I $Root --target linux-x64 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Python compiler Linux parity build failed." }
  $PythonLinuxHash = (Get-FileHash $ParityLinux -Algorithm SHA256).Hash
  & $SelfHostedCompiler $Source $ParityLinux -I $Root --target linux-x64 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Self-hosted Linux parity build failed." }
  $SelfHostedLinuxHash = (Get-FileHash $ParityLinux -Algorithm SHA256).Hash
  if ($PythonLinuxHash -ne $SelfHostedLinuxHash) {
    throw "Linux compiler output differs: $PythonLinuxHash != $SelfHostedLinuxHash"
  }
  & $SelfHostedCompiler $Source $ParityLinux -I $Root --target linux-x64 --object-pipeline | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Self-hosted Linux object-pipeline build failed." }
  $ObjectLinuxHash = (Get-FileHash $ParityLinux -Algorithm SHA256).Hash
  if ($PythonLinuxHash -ne $ObjectLinuxHash) {
    throw "Linux object-pipeline output differs: $PythonLinuxHash != $ObjectLinuxHash"
  }
  Write-Host "[OK] linux-x64 byte-identical: $PythonLinuxHash"
}

Write-Host "[OK] windows-x64 byte-identical: $PythonWindowsHash"
Write-Host "[OK] std.video integration tests passed."
