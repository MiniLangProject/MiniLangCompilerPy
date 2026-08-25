<#
.SYNOPSIS
Compile and exercise std.tls against real Schannel and OpenSSL handshakes.

.DESCRIPTION
Requires WSL with OpenSSL 3. The script creates a one-day localhost identity
under build/tls-test, runs positive client/server exchanges on both targets,
and verifies that hostname mismatches fail closed.
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Compiler
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Compiler = [System.IO.Path]::GetFullPath((Join-Path $Root $Compiler))
$Artifacts = Join-Path $Root "build\tls-test"
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null

if (-not (Test-Path -LiteralPath $Compiler -PathType Leaf)) { throw "Compiler not found: $Compiler" }
if ($null -eq (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { throw "WSL is required" }

function Invoke-Compiler {
  param([string]$Source, [string]$Output, [switch]$Linux)
  $arguments = @($Source, $Output, "-I", $Root)
  if ($Linux) { $arguments += @("--target", "linux-x64") }
  if ([System.IO.Path]::GetExtension($Compiler) -ieq ".py") {
    & python $Compiler @arguments
  } else {
    & $Compiler @arguments
  }
  if ($LASTEXITCODE -ne 0) { throw "TLS fixture compilation failed: $Source" }
}

function Wait-TestProcess {
  param([System.Diagnostics.Process]$Process, [string]$Label)
  if (-not $Process.WaitForExit(15000)) {
    Stop-Process -Id $Process.Id -Force
    throw "$Label timed out"
  }
  $Process.Refresh()
  return $Process.ExitCode
}

$linuxRoot = (& wsl.exe wslpath -a -u ($Root -replace '\\', '/')).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($linuxRoot)) { throw "Could not map repository path into WSL" }
$certificateCommand = "cd '$linuxRoot' && openssl req -x509 -newkey rsa:2048 -sha256 -nodes -keyout build/tls-test/server.key -out build/tls-test/server.crt -days 1 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' >/dev/null 2>&1 && openssl pkcs12 -export -out build/tls-test/server.pfx -inkey build/tls-test/server.key -in build/tls-test/server.crt -passout pass:test-password >/dev/null 2>&1 && openssl x509 -in build/tls-test/server.crt -outform DER | openssl dgst -sha256 -binary > build/tls-test/server.sha256"
& wsl.exe bash -lc $certificateCommand
if ($LASTEXITCODE -ne 0) { throw "OpenSSL test-certificate generation failed" }

$serverSource = Join-Path $Root "tests\tls_native_server.ml"
$clientSource = Join-Path $Root "tests\tls_native_client.ml"
$windowsServer = Join-Path $Artifacts "tls_server.exe"
$windowsClient = Join-Path $Artifacts "tls_client.exe"
$linuxServer = Join-Path $Artifacts "tls_server_linux"
$linuxClient = Join-Path $Artifacts "tls_client_linux"
Invoke-Compiler $serverSource $windowsServer
Invoke-Compiler $clientSource $windowsClient
Invoke-Compiler $serverSource $linuxServer -Linux
Invoke-Compiler $clientSource $linuxClient -Linux

$env:MINILANG_TLS_TEST_PASSWORD = "test-password"
foreach ($negative in @($false, $true)) {
  $suffix = if ($negative) { "bad-host" } else { "ok" }
  $serverOut = Join-Path $Artifacts "windows-server-$suffix.log"
  $serverErr = Join-Path $Artifacts "windows-server-$suffix.err"
  $server = Start-Process -FilePath $windowsServer -WorkingDirectory $Root -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -WindowStyle Hidden -PassThru
  Start-Sleep -Milliseconds 300
  if ($negative) { & $windowsClient "bad-host" } else { & $windowsClient }
  $clientExit = $LASTEXITCODE
  $serverExit = Wait-TestProcess $server "Windows TLS server"
  if (-not $negative -and ($clientExit -ne 0 -or $serverExit -ne 0)) { throw "Windows Schannel roundtrip failed" }
  if ($negative -and $clientExit -eq 0) { throw "Windows Schannel accepted the wrong hostname" }
}

$linuxServerPath = "$linuxRoot/build/tls-test/tls_server_linux"
$linuxClientPath = "$linuxRoot/build/tls-test/tls_client_linux"
foreach ($negative in @($false, $true)) {
  $suffix = if ($negative) { "bad-host" } else { "ok" }
  $serverOut = Join-Path $Artifacts "linux-server-$suffix.log"
  $serverErr = Join-Path $Artifacts "linux-server-$suffix.err"
  $serverCommand = "cd '$linuxRoot' && exec '$linuxServerPath'"
  $server = Start-Process -FilePath "wsl.exe" -ArgumentList @("bash", "-lc", $serverCommand) -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -WindowStyle Hidden -PassThru
  Start-Sleep -Milliseconds 300
  $clientCommand = "cd '$linuxRoot' && '$linuxClientPath'"
  if ($negative) { $clientCommand += " bad-host" }
  & wsl.exe bash -lc $clientCommand
  $clientExit = $LASTEXITCODE
  $serverExit = Wait-TestProcess $server "Linux TLS server"
  if (-not $negative -and ($clientExit -ne 0 -or $serverExit -ne 0)) { throw "Linux OpenSSL roundtrip failed" }
  if ($negative -and $clientExit -eq 0) { throw "Linux OpenSSL accepted the wrong hostname" }
}

Write-Host "[OK] native Schannel and OpenSSL TLS integration"
