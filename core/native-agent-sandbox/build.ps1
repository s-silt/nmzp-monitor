param([switch]$EnableOwnedWfp)
# Build the native supervisor with in-box csc.exe. Outputs MUST stay outside this source tree.
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$SrcDir = Join-Path $Here "src"
$OutDir = $env:NMZP_NAS_OUTDIR
if (-not $OutDir) {
    $OutDir = Join-Path $env:TEMP "nmzp-nas-build"
}

$OutDir = [System.IO.Path]::GetFullPath($OutDir)
$HereFull = [System.IO.Path]::GetFullPath($Here)
if ($OutDir.StartsWith($HereFull, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Error "refusing to write build outputs into core/native-agent-sandbox (pack would pick them up). Set NMZP_NAS_OUTDIR."
    exit 2
}

if (-not (Test-Path $Csc)) {
    Write-Error "csc.exe not found at $Csc"
    exit 2
}

$EgressDir = Join-Path (Split-Path $Here) "native-egress-filter\src"
$Sources = @(
    (Join-Path $SrcDir "NativeMethods.cs"),
    (Join-Path $SrcDir "Util.cs"),
    (Join-Path $SrcDir "Launch.cs"),
    (Join-Path $SrcDir "Brokered.cs"),
    (Join-Path $SrcDir "Controller.cs"),
    (Join-Path $SrcDir "InternalDispatch.cs"),
    (Join-Path $SrcDir "Privileged.cs"),
    (Join-Path $SrcDir "Probe.cs"),
    (Join-Path $SrcDir "SelfTest.cs"),
    (Join-Path $SrcDir "PureSelfTest.cs"),
    (Join-Path $SrcDir "Program.cs"),
    (Join-Path $EgressDir "WfpNative.cs"),
    (Join-Path $EgressDir "Json.cs"),
    (Join-Path $EgressDir "EgressCore.cs"),
    (Join-Path $EgressDir "StateMachine.cs"),
    (Join-Path $EgressDir "OwnedSession.cs"),
    (Join-Path $EgressDir "EgressApply.cs")
)
foreach ($s in $Sources) {
    if (-not (Test-Path $s)) {
        Write-Error "missing source $s"
        exit 2
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Out = Join-Path $OutDir "NativeAgentSandbox.exe"

$Defines = if ($EnableOwnedWfp) { "/define:TRACE,NMZP_ENABLE_OWNED_WFP" } else { "/define:TRACE" }
& $Csc /nologo /noconfig /fullpaths /utf8output /optimize+ /warn:4 /warnaserror- `
    /target:exe /platform:x64 /debug- $Defines `
    /main:NativeAgentSandbox.Program `
    /reference:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll" `
    /reference:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll" `
    /reference:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Core.dll" `
    /out:$Out `
    $Sources

if ($LASTEXITCODE -ne 0) {
    Write-Error "csc failed with exit $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "built $Out"
exit 0
