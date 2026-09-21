import { AGENT_CATALOG } from "./agent-catalog.ts";
/** Runs only OS metadata commands. Candidate programs, scripts and command lines are never executed/read. */
export function windowsDiscoveryScript(paths: string[], home: string): string {
  const config = Buffer.from(
    JSON.stringify({
      paths,
      home,
      adapters: AGENT_CATALOG.filter((a) => !a.unsupported && a.form !== "extension"),
    }),
    "utf8",
  ).toString("base64");
  return `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${config}'))|ConvertFrom-Json
$records=[Collections.Generic.List[object]]::new(); $files=[Collections.Generic.List[object]]::new(); $procs=[Collections.Generic.List[object]]::new()
$states=@{registry='ok';appx='partial';processes='partial';path='partial'}
function Publish-Partial { $phase=$states.Clone();$phase.processes='partial';$phase.path='partial';@{records=@($records.ToArray());files=@($files.ToArray());processes=@();states=$phase}|ConvertTo-Json -Depth 8 -Compress }
$targets=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
function Match-Name($name,$adapter){foreach($n in $adapter.names){if($name -match ('^'+[regex]::Escape($n)+'(?:$|[ (]v?[0-9]| \\(User\\)$| \\(System\\)$)')){return $true}};return $false}
foreach($root in @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall')){
 try{if(Test-Path -LiteralPath $root){$keys=@(Get-ChildItem -LiteralPath $root -ErrorAction Stop);if($keys.Count -gt 2000){$states.registry='partial'};foreach($key in ($keys|Select-Object -First 2000)){
  try{$r=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop;foreach($a in $c.adapters){if(Match-Name $r.DisplayName $a){
   $exe=$null;if($r.DisplayIcon){$icon=[string]$r.DisplayIcon;if($icon -match '^"([^"\r\n]+\\.exe)"(?:,[-0-9]+)?$'){$exe=$Matches[1]}elseif($icon -match '^([^"\r\n]+\\.exe)(?:,[-0-9]+)?$'){$exe=$Matches[1]}}
   $near=@();if(!$exe -and $r.DisplayIcon){$ico=([string]$r.DisplayIcon).Trim('"');if($ico -match '^[A-Za-z]:.*[.]ico$' -and (Test-Path -LiteralPath $ico -PathType Leaf)){try{$near=@(Get-ChildItem -LiteralPath (Split-Path -LiteralPath $ico) -Filter '*.exe' -File -ErrorAction Stop|Select-Object -First 32|ForEach-Object {$_.FullName});foreach($n in $near){[void]$targets.Add($n)}}catch{$states.registry='partial'}}}
   $records.Add(@{adapterId=$a.id;version=$r.DisplayVersion;path=$exe;location=$r.InstallLocation;source='registry';sourceId=[string]$key.Name;entryCandidates=$near});if($exe){[void]$targets.Add($exe)}
  }}}catch{$states.registry='partial'}
 }}}catch{$states.registry='permission'}
}
Publish-Partial
$states.appx='ok'
try{foreach($a in $c.adapters){foreach($n in $a.appx){foreach($p in @(Get-AppxPackage -Name $n -ErrorAction Stop)){
 $manifest=$p|Get-AppxPackageManifest -ErrorAction Stop
 foreach($app in $manifest.Package.Applications.Application){if($app.Id -eq 'App' -and $app.Executable -and $app.Executable -notmatch '(^[\\\\/]|:|\\.\\.)'){$exe=Join-Path $p.InstallLocation $app.Executable;$records.Add(@{adapterId=$a.id;version=[string]$p.Version;location=$p.InstallLocation;source='appx';path=$exe});[void]$targets.Add($exe)}}
}}}}catch{$states.appx='permission'}
Publish-Partial
foreach($p in $c.paths){if($p -match '\\.exe$'){[void]$targets.Add([string]$p)}}
foreach($a in $c.adapters){foreach($hint in $a.hints){[void]$targets.Add((Join-Path $c.home $hint))};if($a.command){foreach($dir in @($env:PATH -split ';' | Select-Object -First 128)){if($dir -match '^[A-Za-z]:[\\\\/]' -and $dir -notmatch '(?i)[\\\\/]node_modules[\\\\/]'){$p=Join-Path $dir ($a.command+'.exe');if(Test-Path -LiteralPath $p){[void]$targets.Add($p)}}}}}
try{
 $states.processes='ok'
 $index=@(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,Name)
 $names=@('Code.exe','Code - Insiders.exe');foreach($a in $c.adapters){if($a.command){$names+=($a.command+'.exe')};foreach($n in $a.names){$names+=($n+'.exe')}}
 foreach($p in $targets){$names+=[IO.Path]::GetFileName($p)}
 $candidates=@($index|Where-Object {$names -contains $_.Name});if($candidates.Count -gt 128){$states.processes='partial'}
 $filters=@($candidates|Select-Object -First 128|ForEach-Object {'ProcessId='+[int]$_.ProcessId})
 if($filters.Count){foreach($p in @(Get-CimInstance Win32_Process -Filter ($filters -join ' OR ') -Property ProcessId,ExecutablePath,CreationDate -ErrorAction Stop)){
  try{
   if($p -and $p.ExecutablePath -and $p.CreationDate){$procs.Add(@{pid=[int]$p.ProcessId;path=$p.ExecutablePath;startedAt=([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds()});[void]$targets.Add([string]$p.ExecutablePath)}else{$states.processes='partial'}
  }catch{$states.processes='partial'}
 }}
}catch{$states.processes='permission'}
if($targets.Count -gt 256){$states.processes='partial'}
$states.path='ok'
foreach($p in ($targets|Select-Object -First 256)){
 try{if($p -notmatch '^[A-Za-z]:[\\\\/]' -or $p -match '(?i)[\\\\/]node_modules[\\\\/]' -or !(Test-Path -LiteralPath $p -PathType Leaf)){continue}
 $f=Get-Item -LiteralPath $p -ErrorAction Stop;if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}
 $v=$f.VersionInfo;$entry=@{path=$p;product=$v.ProductName;description=$v.FileDescription;version=$v.ProductVersion;signature='Unknown'};$files.Add($entry)
 # Preserve bounded partial metadata if signature verification stalls. No unverified PID published here.
 Publish-Partial
 try{$sig=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;$entry.signature=[string]$sig.Status}catch{$states.path='partial'}
 }catch{$files.Add(@{path=$p;error='permission'});$states.path='permission'}
}
# A second exact process identity read prevents PID reuse during the metadata pass.
$stable=[Collections.Generic.List[object]]::new()
try{$filters=@($procs|ForEach-Object {'ProcessId='+[int]$_.pid});if($filters.Count){$after=@(Get-CimInstance Win32_Process -Filter ($filters -join ' OR ') -Property ProcessId,ExecutablePath,CreationDate -ErrorAction Stop);foreach($r in $procs){$p=$after|Where-Object {$_.ProcessId -eq $r.pid};if($p -and $p.ExecutablePath -eq $r.path -and ([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds() -eq $r.startedAt){$stable.Add($r)}}}}catch{$states.processes='partial'}
@{records=@($records.ToArray());files=@($files.ToArray());processes=@($stable.ToArray());states=$states}|ConvertTo-Json -Depth 8 -Compress
`;
}
