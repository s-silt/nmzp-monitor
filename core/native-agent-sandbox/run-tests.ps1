# Compile outside core/, run empirical self-test, write evidence under acceptance/.
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Nmzp = Split-Path (Split-Path (Split-Path $Here))
$Evidence = Join-Path $Nmzp "acceptance\native-agent-sandbox"
$OutDir = Join-Path $Evidence "out"
$BinDir = Join-Path $env:TEMP "nmzp-nas-build"

$env:NMZP_NAS_OUTDIR = $BinDir
& (Join-Path $Here "build.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Exe = Join-Path $BinDir "NativeAgentSandbox.exe"
& $Exe --self-test --out $OutDir
exit $LASTEXITCODE
