$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'storage-firewall.ps1')
$script:rules=@();$script:keywords=@();$script:admin=$true;$script:ready=$true;$script:writes=0;$script:failAt=0;$script:checks=0
function Check($value,[string]$message){$script:checks++;if(!$value){throw $message}}
function MustFail([scriptblock]$fn,[string]$pattern){try{& $fn;throw 'unexpected_success'}catch{Check ($_.Exception.Message -match $pattern) ('wrong_failure: '+$_.Exception.Message)}}
function Test-StorageAdmin {$script:admin}
function Get-StoragePrerequisites {[pscustomobject]@{met=$script:ready;dnsPath='not_verified'}}
function Read-StorageProgram([string]$Path){[pscustomobject]@{path=$Path;sha256=('a'*64);product='fixture';version='1';signature='NotSigned'}}
function Get-NetFirewallRule {param($PolicyStore,$ErrorAction) $script:rules}
function Get-NetFirewallDynamicKeywordAddress {param([switch]$All,$ErrorAction) $script:keywords}
function Get-NetFirewallApplicationFilter {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {[pscustomobject]@{Program=$InputObject.Program}}}
function New-NetFirewallDynamicKeywordAddress {param($Id,$Keyword,$AutoResolve,$ErrorAction) $script:writes++;if($script:failAt -eq $script:writes){throw 'injected_write_failure'};$script:keywords+= [pscustomobject]@{Id=$Id;Keyword=$Keyword;AutoResolve=$AutoResolve;Addresses=''}}
function New-NetFirewallRule {param($Name,$DisplayName,$Group,$Description,$PolicyStore,$Direction,$Action,$Enabled,$Profile,$Protocol,$Program,$RemoteDynamicKeywordAddresses,$ErrorAction) $script:writes++;$script:rules+=[pscustomobject]@{Name=$Name;Group=$Group;Description=$Description;Direction=$Direction;Action=$Action;Enabled=$Enabled;Profile=$Profile;Program=$Program;RemoteDynamicKeywordAddresses=$RemoteDynamicKeywordAddresses}}
function Remove-NetFirewallRule {param($Name,$PolicyStore,$ErrorAction) $script:writes++;$script:rules=@($script:rules | Where-Object Name -NE $Name)}
function Remove-NetFirewallDynamicKeywordAddress {param($Id,$ErrorAction) $script:writes++;$script:keywords=@($script:keywords | Where-Object Id -NE $Id)}
function Reset {$script:rules=@();$script:keywords=@();$script:writes=0;$script:failAt=0;$script:admin=$true;$script:ready=$true}
$plan=New-StoragePlan @((Join-Path $env:TEMP 'syntheticAgent.exe'));$hash='b'*64
Assert-StoragePlan $plan
Check ($plan.keywords.Count -gt 200) 'catalog_incomplete'
Check (@($plan.keywords | Where-Object {$_.keyword -in @('*.aliyuncs.com','*.myqcloud.com','*')}).Count -eq 0) 'overbroad_cloud_scope'
$script:admin=$false;MustFail {Invoke-StorageApply $plan $hash} 'observation_only';Check ($script:writes -eq 0) 'nonadmin_mutated'
$script:admin=$true;MustFail {Invoke-StorageApply $plan $hash} 'observation_only';Check ($script:writes -eq 0) 'admin_mutated'
$status=Get-StorageStatus $plan $hash
Check ($status.rulesInActiveStore -eq 0) 'fabricated_rule';Check ($status.resolvedKeywords -eq 0) 'unresolved_claimed';Check ($status.liveBlockingEvidence -eq 'not_tested') 'fabricated_live_proof';Check ($script:writes -eq 0) 'status_mutated'
# Seed synthetic pre-existing objects to validate safe cleanup; no installation code is called.
$script:keywords=@(foreach($k in $plan.keywords){[pscustomobject]@{Id=$k.id;Keyword=$k.keyword;AutoResolve=$true;Addresses=''}})
$script:rules=@([pscustomobject]@{Name=(Get-StorageRuleName $plan 0);Group='NMZP-OSS-COS';Description=('plan-sha256:'+$hash);Direction='Outbound';Action='Block';Enabled='True';Profile='Any';Program=$plan.programs[0].path;RemoteDynamicKeywordAddresses=@($plan.keywords.id)})
$before=$script:writes;MustFail {Invoke-StorageApply $plan $hash} 'observation_only';Check ($script:writes -eq $before) 'adopted_existing'
$script:rules[0].Description='foreign';MustFail {Invoke-StorageRemove $plan $hash} 'rule_conflict';Check ($script:writes -eq $before) 'removed_foreign'
$script:rules[0].Description='plan-sha256:'+$hash
$foreign=[pscustomobject]@{Name='foreign';RemoteDynamicKeywordAddresses=@($plan.keywords[0].id)};$script:rules+=$foreign
MustFail {Invoke-StorageRemove $plan $hash} 'foreign_rule_uses_keyword';Check ($script:writes -eq $before) 'removed_shared'
$script:rules=@($script:rules | Where-Object Name -NE 'foreign')
$result=Invoke-StorageRemove $plan $hash;Check $result.removed 'remove_failed';Check ($script:rules.Count -eq 0 -and $script:keywords.Count -eq 0) 'cleanup_incomplete'
Reset
$script:keywords=@([pscustomobject]@{Id=$plan.keywords[0].id;Keyword=$plan.keywords[0].keyword;AutoResolve=$true;Addresses=''});Check ($script:rules.Count -eq 0) 'fixture_not_partial'
$script:failAt=0;$result=Invoke-StorageRemove $plan $hash;Check $result.removed 'partial_remove_failed';Check ($script:keywords.Count -eq 0) 'partial_cleanup_incomplete'
$bad=$plan | ConvertTo-Json -Depth 8 | ConvertFrom-Json;$bad.keywords[0].keyword='*.aliyuncs.com';MustFail {Assert-StoragePlan $bad} 'plan_keyword_invalid'
[pscustomobject]@{ok=$true;checks=$script:checks;osFirewallWrites=0;coverage='mock_control_flow_only'} | ConvertTo-Json
