<#
Build and exercise std.video and std.audio through both compiler implementations
and targets.
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
$AudioSource = Join-Path $Root "tests/audio_stdlib.ml"
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
$WaveFixture = Join-Path $Artifacts "audio-fixture.wav"
$Mp3Fixture = Join-Path $Artifacts "audio-fixture.mp3"
$MidiFixture = Join-Path $Artifacts "audio-fixture.mid"
& $ffmpeg -hide_banner -loglevel error -f lavfi -i "testsrc=size=160x90:rate=30" -t 2 -an -c:v rawvideo -pix_fmt yuv420p -threads 1 -y $Fixture
if ($LASTEXITCODE -ne 0) { throw "FFmpeg fixture generation failed." }
& $ffmpeg -hide_banner -loglevel error -f lavfi -i "testsrc=size=160x90:rate=30" -f lavfi -i "sine=frequency=440:sample_rate=48000" -t 2 -c:v rawvideo -pix_fmt yuv420p -c:a pcm_s16le -threads 1 -y $AudioFixture
if ($LASTEXITCODE -ne 0) { throw "FFmpeg audio fixture generation failed." }
& $ffmpeg -hide_banner -loglevel error -f lavfi -i "sine=frequency=523.25:sample_rate=48000" -t 1 -c:a pcm_s16le -y $WaveFixture
if ($LASTEXITCODE -ne 0) { throw "FFmpeg WAV fixture generation failed." }
& $ffmpeg -hide_banner -loglevel error -f lavfi -i "sine=frequency=659.25:sample_rate=48000" -t 1 -c:a libmp3lame -q:a 5 -y $Mp3Fixture
if ($LASTEXITCODE -ne 0) { throw "FFmpeg MP3 fixture generation failed." }
[IO.File]::WriteAllBytes($MidiFixture, [byte[]]@(
  0x4d,0x54,0x68,0x64,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x01,0x00,0x60,
  0x4d,0x54,0x72,0x6b,0x00,0x00,0x00,0x16,0x00,0xff,0x51,0x03,0x07,0xa1,
  0x20,0x00,0xc0,0x00,0x00,0x90,0x3c,0x64,0x60,0x80,0x3c,0x40,0x00,0xff,
  0x2f,0x00))

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

$PythonAudioWindows = Join-Path $WindowsArtifacts "audio-python.exe"
$SelfHostedAudioWindows = Join-Path $WindowsArtifacts "audio-selfhosted.exe"
& $Python $PythonCompiler $AudioSource $PythonAudioWindows -I $Root --target windows-x64
if ($LASTEXITCODE -ne 0) { throw "Python compiler Windows audio build failed." }
& $PythonAudioWindows $WaveFixture $Mp3Fixture $MidiFixture
if ($LASTEXITCODE -ne 0) { throw "Python compiler Windows audio playback test failed." }
& $SelfHostedCompiler $AudioSource $SelfHostedAudioWindows -I $Root --target windows-x64
if ($LASTEXITCODE -ne 0) { throw "Self-hosted Windows audio build failed." }
& $SelfHostedAudioWindows $WaveFixture $Mp3Fixture $MidiFixture
if ($LASTEXITCODE -ne 0) { throw "Self-hosted Windows audio playback test failed." }
$PythonAudioWindowsHash = (Get-FileHash $PythonAudioWindows -Algorithm SHA256).Hash
$SelfHostedAudioWindowsHash = (Get-FileHash $SelfHostedAudioWindows -Algorithm SHA256).Hash
if ($PythonAudioWindowsHash -ne $SelfHostedAudioWindowsHash) {
  throw "Windows audio compiler output differs: $PythonAudioWindowsHash != $SelfHostedAudioWindowsHash"
}

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

  $PythonAudioLinux = Join-Path $LinuxArtifacts "audio-python"
  $SelfHostedAudioLinux = Join-Path $LinuxArtifacts "audio-selfhosted"
  & $Python $PythonCompiler $AudioSource $PythonAudioLinux -I $Root --target linux-x64
  if ($LASTEXITCODE -ne 0) { throw "Python compiler Linux audio build failed." }
  & $SelfHostedCompiler $AudioSource $SelfHostedAudioLinux -I $Root --target linux-x64
  if ($LASTEXITCODE -ne 0) { throw "Self-hosted Linux audio build failed." }

  $WslArtifacts = "$WslRoot/build/native/video"
  & wsl.exe -d $WslDistribution -- bash -lc "cd '$WslArtifacts/linux-x64' && chmod +x video-python video-selfhosted audio-python audio-selfhosted && ./video-python ../video-fixture.avi ../video-audio-fixture.avi && ./video-selfhosted ../video-fixture.avi ../video-audio-fixture.avi && ./audio-python ../audio-fixture.wav ../audio-fixture.mp3 ../audio-fixture.mid && ./audio-selfhosted ../audio-fixture.wav ../audio-fixture.mp3 ../audio-fixture.mid"
  if ($LASTEXITCODE -ne 0) { throw "Linux playback test failed." }

  $PythonAudioLinuxHash = (Get-FileHash $PythonAudioLinux -Algorithm SHA256).Hash
  $SelfHostedAudioLinuxHash = (Get-FileHash $SelfHostedAudioLinux -Algorithm SHA256).Hash
  if ($PythonAudioLinuxHash -ne $SelfHostedAudioLinuxHash) {
    throw "Linux audio compiler output differs: $PythonAudioLinuxHash != $SelfHostedAudioLinuxHash"
  }

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
Write-Host "[OK] std.audio windows-x64 byte-identical: $PythonAudioWindowsHash"
if (-not $SkipLinux) { Write-Host "[OK] std.audio linux-x64 byte-identical: $PythonAudioLinuxHash" }
Write-Host "[OK] std.video and std.audio integration tests passed."
