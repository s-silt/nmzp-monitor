# Explicit original-machine administrator operation. This file is never executed by normal join/probe.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet('Install','Upgrade','Enroll','Revoke','Uninstall','Verify')][string]$Action,
 [string]$Package,[string]$ManifestSha256,[string]$CredentialsFile,[string]$CollectorUserSid
)
$ErrorActionPreference='Stop'
$name='NMZPProbe'
$program=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $name
$data=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $name
$private=Join-Path $data 'private'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run explicitly from an elevated administrator PowerShell; this script never launches UAC'}
function NoLinks([string]$Path) {
 $p=[IO.Path]::GetFullPath($Path)
 while($p){if((Test-Path -LiteralPath $p) -and ((Get-Item -Force -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse path rejected'};$p=[IO.Path]::GetDirectoryName($p)}
}
function Invoke-NmzpSc([string[]]$ScArgs){& "$env:WINDIR\System32\sc.exe" @ScArgs | Out-Null;if($LASTEXITCODE -ne 0){throw 'SCM operation failed'}}
function Acl([string]$Path,[string]$ServiceRights,[string]$UserSid='', [bool]$Readable=$false) {
 NoLinks $Path
 $isDir=(Get-Item -Force -LiteralPath $Path).PSIsContainer
 $acl=if($isDir){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 $inherit=if($isDir){[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[Security.AccessControl.InheritanceFlags]::None}
 foreach($pair in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@($script:serviceSid,$ServiceRights))){
  $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($pair[0]),[Security.AccessControl.FileSystemRights]$pair[1],$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow);$acl.AddAccessRule($rule)
 }
 if($Readable){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute',$inherit,'None','Allow'))}
 if($UserSid){
  # User may replace mailbox children, but cannot delete/change the protected public directory itself.
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($UserSid),'ReadAndExecute,Write','None','None','Allow'))
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($UserSid),'Modify',$inherit,'InheritOnly','Allow'))
 }
 Set-Acl -LiteralPath $Path -AclObject $acl
}
function VerifyPackage([string]$Path,[string]$Hash){
 NoLinks $Path
 if($Hash -notmatch '^[a-f0-9]{64}$'){throw 'Review and supply the exact manifest SHA256'}
 $manifest=Join-Path $Path 'manifest.tsv'
 if((Get-Item -LiteralPath $manifest).Length -gt 1MB -or (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Hash){throw 'Manifest mismatch'}
 $expected=@{};$total=0L
 foreach($line in [IO.File]::ReadAllLines($manifest)){
  $parts=$line.Split("`t")
  if($parts.Length -ne 2 -or $parts[0] -notmatch '^[a-f0-9]{64}$' -or $parts[1] -notmatch '^[A-Za-z0-9_./-]+$' -or $parts[1].StartsWith('/') -or @($parts[1].Split('/') | Where-Object {$_ -in @('','.','..')}).Count -or $expected.ContainsKey($parts[1])){throw 'Invalid manifest entry'}
  $expected[$parts[1]]=$parts[0];if($expected.Count -gt 4096){throw 'File limit'}
 }
 foreach($required in @('node.exe','ProbeService.exe','runtime/probe-service-main.ts')){if(!$expected.ContainsKey($required)){throw 'Incomplete package'}}
 # Enumeration is constrained to the nominated package, not a disk scan; reject links before descending.
 $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue([IO.Path]::GetFullPath($Path));$seen=0
 while($queue.Count){foreach($item in Get-ChildItem -Force -LiteralPath $queue.Dequeue()){
  NoLinks $item.FullName
  if($item.PSIsContainer){if($item.FullName.Length - $Path.Length -gt 600){throw 'Depth limit'};$queue.Enqueue($item.FullName);continue}
  $rel=$item.FullName.Substring([IO.Path]::GetFullPath($Path).TrimEnd('\').Length+1).Replace('\','/')
  if($rel -eq 'manifest.tsv'){continue}
  if(!$expected.ContainsKey($rel) -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected[$rel]){throw 'Package content mismatch'}
  $seen++;$total+=$item.Length;if($total -gt 2GB -or $seen -gt 4096){throw 'Package resource limit'}
 }}
 if($seen -ne $expected.Count){throw 'Missing package file'}
}
function CurrentService(){Get-CimInstance Win32_Service -Filter "Name='NMZPProbe'"}
function OwnedService($s){if($s -and ($s.StartName -ne 'NT SERVICE\NMZPProbe' -or !$s.PathName.StartsWith('"'+$program+'\releases\',[StringComparison]::OrdinalIgnoreCase))){throw 'Existing service is not an owned NMZPProbe service'}}
NoLinks $program;NoLinks $data
$service=CurrentService;OwnedService $service
if($Action -eq 'Uninstall'){
 if($service){if($service.State -ne 'Stopped'){Stop-Service -Name $name;(Get-Service $name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))};Invoke-NmzpSc @('delete',$name)}
 Write-Output 'Service removed. Program/data/keys remain for manual review and removal. CT binding is unchanged; revoke it explicitly.';return
}
if($Action -in @('Enroll','Revoke')){
 if(!$service){throw 'Install the service first'}
 if($service.PathName -notmatch '^"([^"\r\n]+\\ProbeService.exe)" --service ([a-f0-9]{64})$'){throw 'Unexpected service configuration'}
 $release=Split-Path -Parent $Matches[1];VerifyPackage $release $Matches[2]
 $secret=Read-Host 'CT administrator token (not written to disk or process arguments)' -AsSecureString
 $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
 try {
  $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=Join-Path $release 'node.exe';$psi.Arguments='--experimental-strip-types "'+(Join-Path $release 'runtime\probe-service-setup.ts')+'" '+$Action.ToLowerInvariant()+' "'+$private+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardInput=$true;$psi.WorkingDirectory=$release
  $psi.EnvironmentVariables.Remove('NODE_OPTIONS');$psi.EnvironmentVariables.Remove('NODE_PATH')
  $p=[Diagnostics.Process]::Start($psi);$p.StandardInput.WriteLine([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr));$p.StandardInput.Close();if(!$p.WaitForExit(20000)){$p.Kill();throw 'Enrollment timed out'};if($p.ExitCode -ne 0){throw 'Enrollment rejected'}
 }finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr);$secret.Dispose()}
 if($Action -eq 'Enroll'){Start-Service -Name $name;Write-Output 'Signed heartbeat mode required. Stop the old user probe manually; run the tokenless collector as the nominated user.'};return
}
if($Action -eq 'Verify'){
 if(!$service){throw 'Service missing'}
 if($service.PathName -notmatch '^"([^"\r\n]+\\ProbeService.exe)" --service ([a-f0-9]{64})$'){throw 'Unexpected service configuration'}
 VerifyPackage (Split-Path -Parent $Matches[1]) $Matches[2]
 $service | Select-Object Name,StartName,State,StartMode
 & "$env:WINDIR\System32\sc.exe" sdshow $name
 Get-Acl -LiteralPath $program,$private,(Join-Path $private 'probe-private.pem') | Select-Object Path,Owner,AccessToString
 if(Test-Path -LiteralPath (Join-Path $private 'health.json')){Get-Content -LiteralPath (Join-Path $private 'health.json')}
 Write-Output 'This is inspection evidence, not a cross-account denial or protection acceptance.';return
}
if($Action -eq 'Install' -and $service){throw 'Already installed; use Upgrade'}
if($Action -eq 'Upgrade' -and !$service){throw 'No owned service to upgrade'}
$Package=[IO.Path]::GetFullPath($Package);VerifyPackage $Package $ManifestSha256
if($Action -eq 'Install'){
 if((Test-Path -LiteralPath $program) -or (Test-Path -LiteralPath $data)){throw 'Existing directories require manual review; no overwrite or automatic deletion'}
 if($CollectorUserSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$'){throw 'Specify the actual local/domain interactive user SID, never a broad group'}
 $creds=Get-Content -Raw -LiteralPath $CredentialsFile | ConvertFrom-Json
 foreach($field in @('deviceId','token','url','caPem','fingerprintSha256')){if($creds.$field -isnot [string] -or !$creds.$field){throw 'Invalid existing device credentials'}}
 if(!$creds.url.StartsWith('https://') -or $creds.fingerprintSha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Pinned HTTPS credentials required'}
}
# Derive the documented service SID through Windows lookup after creating the STOPPED service.
$release=Join-Path (Join-Path $program 'releases') ($ManifestSha256.Substring(0,16)+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$bin='"'+(Join-Path $release 'ProbeService.exe')+'" --service '+$ManifestSha256
$oldBin=if($service){$service.PathName}else{$null};$wasRunning=$service -and $service.State -eq 'Running';$created=$false
try {
 if(!$service){Invoke-NmzpSc @('create',$name,'binPath=',$bin,'start=','demand','obj=','NT SERVICE\NMZPProbe');$created=$true}
 $script:serviceSid=([Security.Principal.NTAccount]::new('NT SERVICE',$name)).Translate([Security.Principal.SecurityIdentifier]).Value
 if($created){
  New-Item -ItemType Directory -Path $program | Out-Null;Acl $program 'ReadAndExecute' '' $true
  New-Item -ItemType Directory -Path $data | Out-Null;Acl $data 'ReadAndExecute' '' $true
  foreach($dir in @($private,(Join-Path $private '.nmzp'),(Join-Path $private 'tmp'),(Join-Path $private 'AppData'),(Join-Path $private 'AppData\Roaming'),(Join-Path $private 'AppData\Local'))){New-Item -ItemType Directory -Path $dir | Out-Null;Acl $dir 'Modify'}
  $public=Join-Path $data 'public';New-Item -ItemType Directory -Path $public | Out-Null;Acl $public 'ReadAndExecute' $CollectorUserSid
  $utf8=[Text.UTF8Encoding]::new($false);[IO.File]::WriteAllText((Join-Path $private '.nmzp\credentials.json'),($creds | ConvertTo-Json -Depth 5),$utf8)
  New-Item -ItemType Directory -Path (Join-Path $program 'releases') | Out-Null;Acl (Join-Path $program 'releases') 'ReadAndExecute' '' $true
 }
 NoLinks (Join-Path $program 'releases');New-Item -ItemType Directory -Path $release | Out-Null;Acl $release 'ReadAndExecute' '' $true
 # Target is new and protected before copying any executable. Reverify the copy before execution.
 Copy-Item -LiteralPath (Join-Path $Package 'node.exe'),(Join-Path $Package 'ProbeService.exe'),(Join-Path $Package 'manifest.tsv'),(Join-Path $Package 'runtime') -Destination $release -Recurse
 foreach($item in Get-ChildItem -Force -LiteralPath $release -Recurse){Acl $item.FullName 'ReadAndExecute' '' $true}
 VerifyPackage $release $ManifestSha256
 Invoke-NmzpSc @('sidtype',$name,'unrestricted');Invoke-NmzpSc @('sdset',$name,'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCLOCRRC;;;AU)')
 if($created){
  # Sanitise Node preload variables before the only setup invocation; no candidate programs run.
  $savedOptions=$env:NODE_OPTIONS;$savedPath=$env:NODE_PATH
  try{$env:NODE_OPTIONS=$null;$env:NODE_PATH=$null;& (Join-Path $release 'node.exe') --experimental-strip-types (Join-Path $release 'runtime\probe-service-setup.ts') init $private;if($LASTEXITCODE -ne 0){throw 'Private key initialization failed'}}finally{$env:NODE_OPTIONS=$savedOptions;$env:NODE_PATH=$savedPath}
  foreach($file in @('probe-private.pem','enrollment.json','.nmzp\credentials.json')){Acl (Join-Path $private $file) 'Modify'}
  Write-Output 'Installed STOPPED. Review private enrollment.json and run manage.ps1 -Action Enroll to explicitly require signatures at CT.'
 }else{
  if($wasRunning){Stop-Service $name;(Get-Service $name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))}
  Invoke-NmzpSc @('config',$name,'binPath=',$bin)
  if($wasRunning){
   $switchedAt=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();Start-Service $name;(Get-Service $name).WaitForStatus('Running',[TimeSpan]::FromSeconds(90))
   $deadline=[DateTime]::UtcNow.AddSeconds(90);$ready=$false
   do{Start-Sleep -Seconds 2;try{$health=Get-Content -Raw -LiteralPath (Join-Path $private 'health.json') | ConvertFrom-Json;$ready=$health.ok -eq $true -and $health.checkedAt -ge $switchedAt}catch{} }while(!$ready -and [DateTime]::UtcNow -lt $deadline)
   if(!$ready){throw 'New release did not obtain a fresh signed heartbeat'}
  }
  Write-Output 'Upgrade switched. Old release retained for reviewed rollback; CT binding/key unchanged.'
 }
 Invoke-NmzpSc @('config',$name,'start=','delayed-auto')
}catch{
 if($created){try{Invoke-NmzpSc @('delete',$name)}catch{};Write-Warning 'Install failed. Service registration removed where possible; staged program/private data retained for manual inspection.'}
 elseif($oldBin){try{if((Get-Service $name).Status -ne 'Stopped'){Stop-Service $name;(Get-Service $name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))};Invoke-NmzpSc @('config',$name,'binPath=',$oldBin);if($wasRunning){Start-Service $name};Write-Warning 'Previous service command restored; CT binding unchanged'}catch{Write-Warning 'Rollback failed; inspect SCM and retained releases. No bearer-only fallback was enabled.'}}
 throw
}
