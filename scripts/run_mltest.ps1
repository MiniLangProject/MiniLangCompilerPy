<#
Build mltest, discover tagged tests, compile the generated runner, and execute it.
#>
param(
  [string]$TestRoot = "",
  [string]$Python = "python",
  [string]$CompilerScript = "",
  [string]$ArtifactsDir = "",
  [string[]]$TestArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($TestRoot)) { $TestRoot = Join-Path $Root "tests\mltest_fixture" }
if ([string]::IsNullOrWhiteSpace($CompilerScript)) { $CompilerScript = Join-Path $Root "mlc_win64.py" }
if ([string]::IsNullOrWhiteSpace($ArtifactsDir)) { $ArtifactsDir = Join-Path $Root "build\mltest" }
$TestRoot = [System.IO.Path]::GetFullPath($TestRoot)
$CompilerScript = [System.IO.Path]::GetFullPath($CompilerScript)
$ArtifactsDir = [System.IO.Path]::GetFullPath($ArtifactsDir)
New-Item -ItemType Directory -Force -Path $ArtifactsDir | Out-Null

$DiscoveryTool = Join-Path $ArtifactsDir "mltest.exe"
$GeneratedRunner = Join-Path $ArtifactsDir "runner.ml"
$TestExecutable = Join-Path $ArtifactsDir "tests.exe"

& $Python $CompilerScript (Join-Path $Root "tools\mltest.ml") $DiscoveryTool -I $Root
if ($LASTEXITCODE -ne 0) { throw "mltest compilation failed with exit code $LASTEXITCODE" }
& $DiscoveryTool generate $TestRoot $GeneratedRunner
if ($LASTEXITCODE -ne 0) { throw "mltest discovery failed with exit code $LASTEXITCODE" }
& $Python $CompilerScript $GeneratedRunner $TestExecutable -I $Root
if ($LASTEXITCODE -ne 0) { throw "generated test-runner compilation failed with exit code $LASTEXITCODE" }
& $TestExecutable @TestArguments
exit $LASTEXITCODE
