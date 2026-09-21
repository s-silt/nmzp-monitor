# Explicit original-machine operation only. Never called by join/probe or auto UAC.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Plan','Status','Apply','Remove')][string]$Action,
 [string[]]$Program,[Parameter(Mandatory=$true)][string]$PlanFile,[string]$PlanSha256,[switch]$AcknowledgeDnsLimits)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'storage-firewall.ps1')
try {
 if($Action -eq 'Apply'){throw 'observation_only_firewall_apply_disabled'}
 Assert-StorageLocalPath $PlanFile
 if($Action -eq 'Plan'){
  if(Test-Path -LiteralPath $PlanFile){throw 'plan_exists_choose_new_path'}
  $plan=New-StoragePlan $Program
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($plan | ConvertTo-Json -Depth 8))
  $stream=[IO.File]::Open($PlanFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  [pscustomobject]@{planFile=$PlanFile;planSha256=(Get-FileHash -LiteralPath $PlanFile -Algorithm SHA256).Hash.ToLowerInvariant();changedFirewall=$false;reviewRequired='Observation only: this release cannot apply network block rules; the plan is static metadata, not traffic evidence'} | ConvertTo-Json
 }else{
  if((Get-Item -LiteralPath $PlanFile).Length -gt 256KB){throw 'plan_size'}
  $bytes=[IO.File]::ReadAllBytes($PlanFile);$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  if($PlanSha256 -cnotmatch '^[a-f0-9]{64}$' -or $hash -cne $PlanSha256){throw 'reviewed_plan_hash_required'}
  $plan=[Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json;Assert-StoragePlan $plan
  if($Action -eq 'Apply'){if(!$AcknowledgeDnsLimits){throw 'acknowledge_partial_dns_control_required'};Invoke-StorageApply $plan $hash | ConvertTo-Json -Depth 8}
  elseif($Action -eq 'Remove'){Invoke-StorageRemove $plan $hash | ConvertTo-Json -Depth 8}
  else{Get-StorageStatus $plan $hash | ConvertTo-Json -Depth 8}
 }
}catch{[pscustomobject]@{ok=$false;error=$_.Exception.Message;coverage='unknown';liveBlockingEvidence='not_tested';note='A failed Apply or Remove can leave partial rules. Keep the reviewed plan and inspect Status; do not broadly clear firewall rules.'} | ConvertTo-Json;exit 1}
