# Functions only. No elevation, firewall mutation, DNS query or process launch on load.
Set-StrictMode -Version Latest
function Assert-StorageLocalPath([string]$Path) {
 if($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '[*?\x00-\x1f]'){throw 'local_absolute_path_required'}
 $p=[IO.Path]::GetFullPath($Path)
 $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($p));if($drive.DriveType -ne 'Fixed'){throw 'fixed_local_drive_required'}
 while($p){if((Test-Path -LiteralPath $p) -and ((Get-Item -Force -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'reparse_refused'};$p=[IO.Path]::GetDirectoryName($p)}
}
function Read-StorageProgram([string]$Path) {
 Assert-StorageLocalPath $Path
 $f=Get-Item -Force -LiteralPath $Path -ErrorAction Stop
 if($f.PSIsContainer -or $f.Extension -ine '.exe' -or $f.Length -gt 1GB){throw 'bounded_executable_required'}
 if($f.Name -match '^(node|python[0-9.w]*|pwsh|powershell|cmd|git|bash|wsl|rundll32|svchost|electron|code|chrome|msedge|firefox|curl|wget)\.exe$' -or $f.VersionInfo.ProductName -match 'Node\.js|Python|PowerShell|Windows Command|Google Chrome|Microsoft Edge|Firefox|Visual Studio Code'){throw 'shared_host_refused'}
 $sig=Get-AuthenticodeSignature -LiteralPath $f.FullName
 [pscustomobject]@{path=$f.FullName;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();product=[string]$f.VersionInfo.ProductName;version=[string]$f.VersionInfo.FileVersion;signature=[string]$sig.Status}
}
function Get-StorageEndpoints {
 $c=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'storage-endpoints.json') | ConvertFrom-Json
 if($c.version -ne 1 -or @($c.endpoints).Count -lt 2 -or @($c.endpoints).Count -gt 200){throw 'catalog_invalid'}
 foreach($e in $c.endpoints){if($e -notmatch '^(oss-[a-z0-9-]+\.aliyuncs\.com|[a-z0-9-]+\.oss\.aliyuncs\.com|cos\.[a-z0-9-]+\.myqcloud\.com|cos-internal\.accelerate\.tencentcos\.cn)$'){throw 'catalog_scope_invalid'}}
 @($c.endpoints | Sort-Object -Unique)
}
function New-StoragePlan([string[]]$Program) {
 if(!$Program -or $Program.Count -gt 8){throw 'one_to_eight_programs_required'}
 $programs=@($Program | ForEach-Object {Read-StorageProgram $_});if(@($programs.path | Sort-Object -Unique).Count -ne $programs.Count){throw 'duplicate_program'}
 $keywords=@(foreach($e in (Get-StorageEndpoints)){foreach($k in @($e,"*.$e")){[pscustomobject]@{id=([guid]::NewGuid().ToString('B'));keyword=$k}}})
 [pscustomobject]@{schema='nmzp.storage-egress.v1';id=[guid]::NewGuid().ToString('D');createdAt=[DateTimeOffset]::Now.ToOffset([TimeSpan]::FromHours(8)).ToString('o');programs=$programs;keywords=$keywords;scope='selected_executable_paths_only';coverage='partial';liveBlockingEvidence='not_tested'}
}
function Assert-StoragePlan($Plan) {
 if($Plan.schema -ne 'nmzp.storage-egress.v1' -or $Plan.id -notmatch '^[a-f0-9-]{36}$' -or ![guid]::TryParse($Plan.id,[ref]([guid]::Empty))){throw 'plan_invalid'}
 if(@($Plan.programs).Count -lt 1 -or @($Plan.programs).Count -gt 8){throw 'plan_programs_invalid'}
 $expected=@(foreach($e in (Get-StorageEndpoints)){$e;"*.$e"})
 if(@($Plan.keywords).Count -ne $expected.Count -or @($Plan.keywords.id | Sort-Object -Unique).Count -ne $expected.Count -or @($Plan.keywords.keyword | Sort-Object -Unique).Count -ne $expected.Count){throw 'plan_keywords_invalid'}
 foreach($k in $Plan.keywords){if($k.keyword -cnotin $expected -or $k.id -notmatch '^\{[a-f0-9-]{36}\}$' -or ![guid]::TryParse($k.id,[ref]([guid]::Empty))){throw 'plan_keyword_invalid'}}
 foreach($p in $Plan.programs){Assert-StorageLocalPath $p.path;if($p.sha256 -notmatch '^[a-f0-9]{64}$'){throw 'program_hash_invalid'}}
 if(@($Plan.programs.path | Sort-Object -Unique).Count -ne @($Plan.programs).Count){throw 'duplicate_program'}
}
function Test-StorageAdmin {([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
function Get-StoragePrerequisites {
 $status=Get-MpComputerStatus -ErrorAction Stop;$pref=Get-MpPreference -ErrorAction Stop;$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
 $met=$status.AntivirusEnabled -and $status.AMRunningMode -eq 'Normal' -and [version]$status.AMProductVersion -ge [version]'4.18.2209.7' -and [int]$pref.EnableNetworkProtection -in @(1,2) -and $profiles.Count -eq 3 -and @($profiles | Where-Object {"$($_.Enabled)" -ne 'True' -or "$($_.AllowLocalFirewallRules)" -eq 'False'}).Count -eq 0
 [pscustomobject]@{met=[bool]$met;dnsPath='not_verified';note='DoH, proxy, VPN, cached IP, DNS race, CNAME and unlisted child executables can bypass this partial control'}
}
function Get-StorageWorld([string]$Store='PersistentStore') {
 $rules=@(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop);$keywords=@(Get-NetFirewallDynamicKeywordAddress -All -ErrorAction Stop)
 if($rules.Count -gt 20000 -or $keywords.Count -gt 10000){throw 'state_limit'}
 [pscustomobject]@{rules=$rules;keywords=$keywords}
}
function Get-StorageRuleName($Plan,[int]$Index){'NMZP-OSS-COS-'+$Plan.id+'-'+$Index}
function Assert-StorageRule($Rule,$Plan,[int]$Index,[string]$Hash) {
 if($Rule.Group -cne 'NMZP-OSS-COS' -or $Rule.Description -cne ('plan-sha256:'+ $Hash) -or "$($Rule.Direction)" -ne 'Outbound' -or "$($Rule.Action)" -ne 'Block' -or "$($Rule.Enabled)" -ne 'True' -or "$($Rule.Profile)" -ne 'Any'){throw 'rule_conflict'}
 $app=@($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
 if($app.Count -ne 1 -or $app[0].Program -ine $Plan.programs[$Index].path){throw 'rule_program_conflict'}
 if((@($Rule.RemoteDynamicKeywordAddresses | ForEach-Object {([guid]$_).ToString('D')} | Sort-Object) -join ',') -ne (@($Plan.keywords.id | ForEach-Object {([guid]$_).ToString('D')} | Sort-Object) -join ',')){throw 'rule_keyword_conflict'}
}
function Get-StorageStatus($Plan,[string]$Hash) {
 $w=Get-StorageWorld 'ActiveStore';$present=0;$hydrated=0;$changed=0
 foreach($k in $Plan.keywords){$found=@($w.keywords | Where-Object {([string]$_.Id).Trim('{}') -ieq ([string]$k.id).Trim('{}')});if($found.Count -eq 1){if($found[0].Keyword -cne $k.keyword -or !$found[0].AutoResolve){throw 'keyword_conflict'};if($found[0].Addresses){$hydrated++}}}
 for($i=0;$i -lt $Plan.programs.Count;$i++){
  $name=Get-StorageRuleName $Plan $i;$rule=@($w.rules | Where-Object Name -EQ $name)
  if($rule.Count -gt 1){throw 'duplicate_rule'};if($rule.Count -eq 1){Assert-StorageRule $rule[0] $Plan $i $Hash;$present++}
  try{if((Read-StorageProgram $Plan.programs[$i].path).sha256 -ne $Plan.programs[$i].sha256){$changed++}}catch{$changed++}
 }
 [pscustomobject]@{checkedAt=[DateTimeOffset]::Now.ToOffset([TimeSpan]::FromHours(8)).ToString('o');rulesInActiveStore=$present;expectedRules=@($Plan.programs).Count;resolvedKeywords=$hydrated;expectedKeywords=@($Plan.keywords).Count;changedOrMissingPrograms=$changed;prerequisites=Get-StoragePrerequisites;coverage='partial';liveBlockingEvidence='not_tested';uploadSizeInspection='unavailable_in_ip_firewall';scope='selected_paths_not_process_tree'}
}
function Invoke-StorageApply($Plan,[string]$Hash) {
 # User requested observation only: no firewall creation path in this release.
 throw 'observation_only_firewall_apply_disabled'
}
function Invoke-StorageRemove($Plan,[string]$Hash) {
 if(!(Test-StorageAdmin)){throw 'requires_admin_no_uac'}
 $w=Get-StorageWorld;$names=@();$keys=@()
 for($i=0;$i -lt $Plan.programs.Count;$i++){
  $name=Get-StorageRuleName $Plan $i;$names+=$name;$rule=@($w.rules | Where-Object Name -EQ $name)
  if($rule.Count -gt 1){throw 'duplicate_rule'};if($rule.Count -eq 1){Assert-StorageRule $rule[0] $Plan $i $Hash}
 }
 foreach($k in $Plan.keywords){
  $found=@($w.keywords | Where-Object {([string]$_.Id).Trim('{}') -ieq ([string]$k.id).Trim('{}')})
  if($found.Count -gt 1){throw 'duplicate_keyword'}
  if($found.Count -eq 1){if($found[0].Keyword -cne $k.keyword -or !$found[0].AutoResolve){throw 'keyword_conflict'};$keys+=$k.id}
 }
 foreach($rule in $w.rules){if($rule.Name -notin $names){foreach($id in @($rule.RemoteDynamicKeywordAddresses)){if($id -and @($keys | Where-Object {([guid]$_) -eq ([guid]$id)}).Count){throw 'foreign_rule_uses_keyword'}}}}
 foreach($name in $names){if(@($w.rules | Where-Object Name -EQ $name).Count){Remove-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop}}
 $after=Get-StorageWorld;if(@($after.rules | Where-Object {$_.Name -in $names}).Count){throw 'rule_remove_unverified_keep_keywords'}
 # Recheck references after removing our rules; never delete a shared keyword.
 foreach($rule in $after.rules){foreach($id in @($rule.RemoteDynamicKeywordAddresses)){if($id -and @($keys | Where-Object {([guid]$_) -eq ([guid]$id)}).Count){throw 'keyword_reference_changed_keep_keywords'}}}
 foreach($id in $keys){Remove-NetFirewallDynamicKeywordAddress -Id $id -ErrorAction Stop}
 $last=Get-StorageWorld;foreach($k in $last.keywords){if(@($keys | Where-Object {([guid]$_) -eq ([guid]$k.Id)}).Count){throw 'keyword_remove_unverified'}}
 [pscustomobject]@{removed=$true;scope='only_exact_reviewed_plan_objects';checkedAt=[DateTimeOffset]::Now.ToOffset([TimeSpan]::FromHours(8)).ToString('o')}
}
