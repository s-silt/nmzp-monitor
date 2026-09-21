# Pure package validation: no service/ACL actions, never executes fixture .exe files.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'manage.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer syntax failed'}
$functions=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('NoLinks','VerifyPackage')},$false)
foreach($fn in $functions){Invoke-Expression $fn.Extent.Text}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('nmzp-service-package-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'runtime') -Force | Out-Null
$utf8=[Text.UTF8Encoding]::new($false);$rows=@()
foreach($rel in @('node.exe','ProbeService.exe','runtime/probe-service-main.ts')){
 $p=Join-Path $fixture $rel;[IO.File]::WriteAllText($p,'SYNTHETIC ONLY; never execute',$utf8)
 $rows+=((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()+"`t"+$rel)
}
$manifest=Join-Path $fixture 'manifest.tsv';[IO.File]::WriteAllText($manifest,($rows -join "`n")+"`n",$utf8)
$hash=(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
VerifyPackage $fixture $hash
$rejected=$false;try{VerifyPackage $fixture ('0'*64)}catch{$rejected=$true};if(!$rejected){throw 'Wrong trusted manifest hash accepted'}
[IO.File]::WriteAllText((Join-Path $fixture 'node.exe'),'MODIFIED',$utf8)
$rejected=$false;try{VerifyPackage $fixture $hash}catch{$rejected=$true};if(!$rejected){throw 'Modified binary accepted'}
[IO.File]::WriteAllText($manifest,($rows -join "`n")+"`n"+$rows[0].Replace('node.exe','../node.exe')+"`n",$utf8)
$hash=(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
$rejected=$false;try{VerifyPackage $fixture $hash}catch{$rejected=$true};if(!$rejected){throw 'Traversal accepted'}
Write-Output 'PASS: syntax, exact manifest, modified binary, wrong hash and traversal. No SCM/ACL changes. Synthetic directory retained for manual cleanup:'
Write-Output $fixture
