# Build x64 helper with in-box .NET Framework csc. Output is NOT under core/.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Join-Path $Root "src"
$Csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$Proof = Join-Path $Root "..\..\..\acceptance\native-egress-filter-proof"
$Proof = [System.IO.Path]::GetFullPath($Proof)
$Bin = Join-Path $Proof "bin"
$Out = Join-Path $Bin "NmzpNativeEgressFilter.exe"

if (-not (Test-Path $Csc)) {
    Write-Error "csc.exe not found at $Csc"
    exit 2
}
if (-not (Test-Path $SrcDir)) {
    Write-Error "missing $SrcDir"
    exit 2
}

$files = @(
    (Join-Path $SrcDir "WfpNative.cs"),
    (Join-Path $SrcDir "Json.cs"),
    (Join-Path $SrcDir "EgressCore.cs"),
    (Join-Path $SrcDir "StateMachine.cs"),
    (Join-Path $SrcDir "OwnedSession.cs"),
    (Join-Path $SrcDir "EgressApply.cs"),
    (Join-Path $SrcDir "Program.cs"),
    (Join-Path $SrcDir "SelfTest.cs")
)
foreach ($f in $files) {
    if (-not (Test-Path $f)) { Write-Error "missing $f"; exit 2 }
}

New-Item -ItemType Directory -Force -Path $Bin | Out-Null

& $Csc /nologo /noconfig /fullpaths /utf8output /optimize+ /warn:4 /warnaserror- `
    /target:exe /platform:x64 /debug- /define:TRACE `
    /reference:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll" `
    /reference:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll" `
    /reference:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Core.dll" `
    /out:$Out `
    $files

if ($LASTEXITCODE -ne 0) {
    Write-Error "csc failed with exit $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "built $Out"
exit 0
