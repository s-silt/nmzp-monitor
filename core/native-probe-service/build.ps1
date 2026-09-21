[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutDir)
$ErrorActionPreference='Stop'
$outPath=[IO.Path]::GetFullPath($OutDir)
if(Test-Path -LiteralPath $outPath){throw 'Output must be a new directory'}
New-Item -ItemType Directory -Path $outPath | Out-Null
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(!(Test-Path -LiteralPath $compiler)){throw 'Requires the Windows .NET Framework 4 compiler; no download or installation performed'}
& $compiler /nologo /target:exe /platform:anycpu /optimize+ /r:System.ServiceProcess.dll ("/out:"+(Join-Path $outPath 'ProbeService.exe')) (Join-Path $PSScriptRoot 'ProbeService.cs')
if($LASTEXITCODE -ne 0){throw 'Native service compile failed'}
& (Join-Path $outPath 'ProbeService.exe') --self-test
if($LASTEXITCODE -ne 0){throw 'Native pure self-test failed'}
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $outPath 'ProbeService.exe')
