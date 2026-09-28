# TEST-ONLY disposable Authenticode. Creates a CurrentUser code-signing cert,
# signs a copy of the SEA exe, verifies, mutates one byte, verifies rejection,
# then removes the cert. Not production trust.
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
  New-PSDrive -Name Cert -PSProvider Certificate -Root 'Cert:\' -ErrorAction SilentlyContinue | Out-Null
}
$out = 'C:\Users\sxl\Desktop\NMZP\wp10-out'
$src = Join-Path $out 'bin\nmzp.exe'
$copy = Join-Path $out 'sign\nmzp-authenticode-test.exe'
$mut = Join-Path $out 'sign\nmzp-authenticode-mutated.exe'
New-Item -ItemType Directory -Force -Path (Join-Path $out 'sign') | Out-Null
Copy-Item -Force $src $copy
Copy-Item -Force $src $mut
$thumb = $null
$result = [ordered]@{ label = 'TEST-ONLY self-signed Authenticode. NOT production trust.'; at = (Get-Date).ToString('o') }
try {
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=NMZP-WP10-TEST-ONLY-DISPOSABLE' -CertStoreLocation 'Cert:\CurrentUser\My' -HashAlgorithm SHA256 -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
  $thumb = $cert.Thumbprint
  $result.thumbprintPrefix = $thumb.Substring(0, 8)
  $sig = Set-AuthenticodeSignature -FilePath $copy -Certificate $cert -HashAlgorithm SHA256
  $result.signStatus = [string]$sig.Status
  $result.signStatusMessage = [string]$sig.StatusMessage
  $v1 = Get-AuthenticodeSignature -FilePath $copy
  $result.verifyOriginal = [string]$v1.Status
  $bytes = [System.IO.File]::ReadAllBytes($mut)
  $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 1
  [System.IO.File]::WriteAllBytes($mut, $bytes)
  $v2 = Get-AuthenticodeSignature -FilePath $mut
  $result.verifyMutated = [string]$v2.Status
  $result.mutationRejected = ($v2.Status -ne $v1.Status) -or ($v2.Status -eq 'HashMismatch') -or ($v2.Status -eq 'NotSigned')
}
catch {
  $result.error = "$_"
}
finally {
  if ($thumb) {
    Remove-Item -Force "Cert:\CurrentUser\My\$thumb" -ErrorAction SilentlyContinue
    $result.certRemoved = -not (Test-Path "Cert:\CurrentUser\My\$thumb")
  }
}
$result | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $out 'results\05-authenticode.json')
$result | ConvertTo-Json
