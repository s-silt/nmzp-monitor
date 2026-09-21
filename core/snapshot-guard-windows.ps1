$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

function Emit-Json($obj) {
  $json = @($obj)[0] | ConvertTo-Json -Compress -Depth 8
  [Console]::Out.WriteLine($json)
}

function Get-UserSid {
  return [System.Security.Principal.WindowsIdentity]::GetCurrent().User
}

function Test-Reparse($item) {
  if (-not $item) { return $false }
  return [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

function Assert-NoReparsePath($path) {
  $cur = [string]$path
  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  while ($cur -and $seen.Add($cur)) {
    if (Test-Path -LiteralPath $cur) {
      $it = Get-Item -LiteralPath $cur -Force
      if (Test-Reparse $it) { throw 'reparse_rejected' }
    }
    $parent = [System.IO.Path]::GetDirectoryName($cur)
    if (-not $parent -or $parent -eq $cur) { break }
    $cur = $parent
  }
}

function Get-AccessAcl($item) {
  $sections = [System.Security.AccessControl.AccessControlSections]::Access
  return $item.GetAccessControl($sections)
}

function Get-Sddl($acl) {
  return [string]$acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
}

function Get-ExplicitAces($acl) {
  $list = New-Object System.Collections.Generic.List[object]
  $rules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
  foreach ($ace in $rules) {
    $list.Add(@{
      sid = [string]$ace.IdentityReference.Value
      type = [string]$ace.AccessControlType
      rights = [int]$ace.FileSystemRights
      inherit = [string]$ace.InheritanceFlags
    })
  }
  return $list
}

function New-OurDenyRule($rights) {
  $sid = Get-UserSid
  return New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid,
    [System.Security.AccessControl.FileSystemRights]$rights,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Deny
  )
}

function Test-OurDenyPresent($acl, $rights) {
  $sid = Get-UserSid
  foreach ($ace in $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
    $r = [int]$ace.FileSystemRights
    if ($ace.IdentityReference -eq $sid -and [string]$ace.AccessControlType -eq 'Deny' -and $r -eq $rights -and [string]$ace.InheritanceFlags -eq 'None') {
      return $true
    }
  }
  return $false
}

function Inspect-Path($path) {
  $out = @{
    exists = $false
    isDir = $false
    reparse = $false
    sddl = $null
    ownerSid = $null
    aces = @()
    error = $null
  }
  if (-not (Test-Path -LiteralPath $path)) { return $out }
  $out.exists = $true
  try {
    $item = Get-Item -LiteralPath $path -Force
    $out.isDir = [bool]$item.PSIsContainer
    $out.reparse = Test-Reparse $item
    if ($out.reparse) { return $out }
    $acl = Get-AccessAcl $item
    $out.sddl = Get-Sddl $acl
    $out.aces = @(Get-ExplicitAces $acl)
  } catch {
    $out.error = 'access_denied'
  }
  return $out
}

function Plan-Deny($path, $rights) {
  Assert-NoReparsePath $path
  $item = Get-Item -LiteralPath $path -Force
  if (Test-Reparse $item) { throw 'reparse_rejected' }
  $acl = Get-AccessAcl $item
  $original = Get-Sddl $acl
  $already = Test-OurDenyPresent $acl $rights
  if (-not $already) {
    [void]$acl.AddAccessRule((New-OurDenyRule $rights))
  }
  $expected = Get-Sddl $acl
  return @{
    ok = $true
    originalSddl = $original
    expectedSddl = $expected
    alreadyPresent = $already
  }
}

function Apply-PlannedDeny($path, $rights, $expectedOriginal, $expectedNew) {
  if (-not $expectedOriginal -or -not $expectedNew) {
    return @{ ok = $false; changed = $false; conflict = $true; error = 'missing_expected' }
  }
  Assert-NoReparsePath $path
  $item = Get-Item -LiteralPath $path -Force
  if (Test-Reparse $item) { throw 'reparse_rejected' }
  $acl = Get-AccessAcl $item
  $current = Get-Sddl $acl
  if ($current -eq $expectedNew) {
    return @{ ok = $true; changed = $false; conflict = $false; originalSddl = $expectedOriginal; expectedSddl = $expectedNew }
  }
  if ($current -ne $expectedOriginal) {
    return @{ ok = $true; changed = $false; conflict = $true; error = 'conflict'; originalSddl = $expectedOriginal; expectedSddl = $expectedNew }
  }
  [void]$acl.AddAccessRule((New-OurDenyRule $rights))
  $item.SetAccessControl($acl)
  try {
    $readback = Get-Sddl (Get-AccessAcl $item)
  } catch {
    return @{ ok = $false; changed = $true; conflict = $false; originalSddl = $expectedOriginal; expectedSddl = $expectedNew; error = 'readback_failed' }
  }
  if ($readback -ne $expectedNew) {
    return @{ ok = $false; changed = $true; conflict = $false; originalSddl = $expectedOriginal; expectedSddl = $expectedNew; error = 'readback_mismatch' }
  }
  return @{ ok = $true; changed = $true; conflict = $false; originalSddl = $expectedOriginal; expectedSddl = $expectedNew }
}

function Restore-Sddl($path, $original, $expected) {
  if (-not $original -or -not $expected) {
    return @{ ok = $true; conflict = $true; skipped = $true; error = 'missing_expected' }
  }
  Assert-NoReparsePath $path
  $item = Get-Item -LiteralPath $path -Force
  if (Test-Reparse $item) { return @{ ok = $true; conflict = $true; skipped = $true } }
  $acl = Get-AccessAcl $item
  $current = Get-Sddl $acl
  if ($current -eq $original) { return @{ ok = $true; conflict = $false; skipped = $true } }
  if ($current -ne $expected) { return @{ ok = $true; conflict = $true; skipped = $true } }
  $acl.SetSecurityDescriptorSddlForm($original, [System.Security.AccessControl.AccessControlSections]::Access)
  $item.SetAccessControl($acl)
  return @{ ok = $true; conflict = $false; skipped = $false }
}

function Test-ZcodeRunning {
  $procs = Get-Process -ErrorAction Stop
  foreach ($pr in $procs) {
    $n = [string]$pr.Name
    if ($n -match '(?i)zcode') { return $true }
    try {
      $e = [string]$pr.Path
      if ($e -and ($e -match '(?i)[\\/]zcode[\\/]')) { return $true }
    } catch {
    }
  }
  return $false
}

try {
  $inputPath = $env:NMZP_SG_INPUT
  if (-not $inputPath) { throw 'sg_input_missing' }
  $payload = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($inputPath))
  $action = [string]$payload.action
  $userSid = [string](Get-UserSid).Value

  if ($action -eq 'who') {
    Emit-Json @{ ok = $true; userSid = $userSid }
    exit 0
  }

  if ($action -eq 'zcode') {
    try {
      $running = Test-ZcodeRunning
      Emit-Json @{ ok = $true; running = $running }
    } catch {
      Emit-Json @{ ok = $false; running = $false; error = 'process_list_failed' }
      exit 1
    }
    exit 0
  }

  if ($action -eq 'inspect') {
    $paths = @($payload.paths)
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($p in $paths) {
      $row = Inspect-Path ([string]$p)
      $row.path = [string]$p
      $items.Add($row)
    }
    Emit-Json @{ ok = $true; userSid = $userSid; items = $items }
    exit 0
  }

  if ($action -eq 'planDeny') {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($payload.items)) {
      $p = [string]$it.path
      $rights = [int]$it.rights
      try {
        $r = Plan-Deny $p $rights
        $r.path = $p
        $rows.Add($r)
      } catch {
        $err = 'access_denied'
        if ([string]$_.Exception.Message -eq 'reparse_rejected') { $err = 'reparse_rejected' }
        $rows.Add(@{ ok = $false; path = $p; error = $err })
      }
    }
    Emit-Json @{ ok = $true; userSid = $userSid; results = $rows }
    exit 0
  }

  if ($action -eq 'addDeny') {
    $failAfter = 0
    if ($payload.PSObject.Properties.Name -contains 'failAfter') {
      $failAfter = [int]$payload.failAfter
    }
    $mutated = 0
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($payload.items)) {
      $p = [string]$it.path
      $rights = [int]$it.rights
      $expectedOriginal = [string]$it.expectedOriginal
      $expectedNew = [string]$it.expectedNew
      if ($failAfter -gt 0 -and $mutated -ge $failAfter) {
        $rows.Add(@{ ok = $false; path = $p; changed = $false; conflict = $false; error = 'injected_failure' })
        continue
      }
      try {
        $r = Apply-PlannedDeny $p $rights $expectedOriginal $expectedNew
        $r.path = $p
        $rows.Add($r)
        if ($r.changed) { $mutated++ }
        elseif ($r.ok -and -not $r.conflict) { $mutated++ }
      } catch {
        $err = 'access_denied'
        if ([string]$_.Exception.Message -eq 'reparse_rejected') { $err = 'reparse_rejected' }
        $rows.Add(@{ ok = $false; path = $p; changed = $false; conflict = $true; error = $err })
      }
    }
    Emit-Json @{ ok = $true; userSid = $userSid; results = $rows }
    exit 0
  }

  if ($action -eq 'restoreSddl') {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($payload.items)) {
      $p = [string]$it.path
      try {
        $r = Restore-Sddl $p ([string]$it.originalSddl) ([string]$it.expectedSddl)
        $r.path = $p
        $rows.Add($r)
      } catch {
        $err = 'access_denied'
        if ([string]$_.Exception.Message -eq 'reparse_rejected') { $err = 'reparse_rejected' }
        $rows.Add(@{ ok = $false; path = $p; error = $err; conflict = $true })
      }
    }
    Emit-Json @{ ok = $true; userSid = $userSid; results = $rows }
    exit 0
  }

  Emit-Json @{ ok = $false; error = 'unknown_action' }
  exit 1
} catch {
  Emit-Json @{ ok = $false; error = 'ps_exception' }
  exit 1
}
