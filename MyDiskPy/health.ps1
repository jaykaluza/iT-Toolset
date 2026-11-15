# My Disk: deeper health checks on one drive, and their fixes. Needs Administrator rights.
#   MD_ACTION=structure  NTFS self-healing state, the "needs a repair" flag and Windows' own list of known corrupt files ($Corrupt). Read-only.
#   MD_ACTION=perms      who may open and change the drive's top folder, and top folders even Administrators can't open. Read-only.
#   MD_ACTION=ransomps   restore copies (shadow copies) of the drive, and Microsoft Defender's ransomware protection setting. Read-only.
#   MD_ACTION=selfheal   turns NTFS self-healing back on (fsutil repair set X: 1).
#   MD_ACTION=permfix    gives SYSTEM and Administrators full control again, removes deny entries against them,
#                        and removes Everyone, Guests and Anonymous from the drive's top folder.
#   MD_ACTION=shadow     makes a restore copy (shadow copy) of the drive now.
#   MD_ACTION=cfa        turns on Microsoft Defender's Controlled folder access (ransomware protection).
# The drive is named by its volume path (\\?\Volume{...}\). Values arrive only as environment variables.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Out($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 5)) }
function Tool($exe, [string[]]$params) {
  # Runs a Windows tool and returns its text; a failing tool must not stop the script.
  $ErrorActionPreference = 'Continue'
  $text = (& $exe @params 2>&1 | ForEach-Object { [string]$_ }) -join "`n"
  [pscustomobject]@{ text = $text.Trim(); code = $LASTEXITCODE }
}
$fsutil = "$env:SystemRoot\System32\fsutil.exe"
$icacls = "$env:SystemRoot\System32\icacls.exe"
try {
  $path = [string]$env:MD_VOLUME
  if ($path -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') { Out @{ ok = $false; error = 'Not a volume path.' }; exit }
  $v = Get-Volume -Path $path
  if (-not $v) { Out @{ ok = $false; error = 'That drive is gone.' }; exit }
  $L = [string]$v.DriveLetter
  $root = if ($L) { "$($L):\" } else { $path }
  switch ($env:MD_ACTION) {
    'structure' {
      $o = [ordered]@{ ok = $true; fs = [string]$v.FileSystemType; health = [string]$v.HealthStatus; status = [string]$v.OperationalStatus }
      if ($L -and $v.FileSystemType -eq 'NTFS') {
        $o.heal = (Tool $fsutil @('repair', 'query', "$($L):")).text
        $o.dirty = (Tool $fsutil @('dirty', 'query', "$($L):")).text
        $o.corrupt = (Tool $fsutil @('repair', 'enumerate', "$($L):", '$Corrupt')).text
      }
      Out $o
    }
    'perms' {
      $acl = Get-Acl -LiteralPath $root
      $rules = @($acl.Access | ForEach-Object {
        $r = $_
        $sid = try { $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { [string]$r.IdentityReference }
        @{ sid = $sid; who = [string]$r.IdentityReference; rights = [int64]$r.FileSystemRights; allow = ([string]$r.AccessControlType -eq 'Allow')
           inheritOnly = (([int]$r.PropagationFlags -band 2) -ne 0) } })
      $ownerSid = try { (New-Object Security.Principal.NTAccount $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
      $blocked = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
        Where-Object { $d = $_.FullName; try { $null = [IO.Directory]::GetFileSystemEntries($d); $false } catch [UnauthorizedAccessException] { $true } catch { $false } } |
        ForEach-Object { $_.Name } | Select-Object -First 30)
      Out @{ ok = $true; owner = [string]$acl.Owner; ownerSid = $ownerSid; rules = $rules; blocked = $blocked }
    }
    'ransomps' {
      $o = [ordered]@{ ok = $true; shadows = $null; newest = $null; cfa = $null }
      try {   # if Windows can't list them, say so rather than report none
        $dates = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Where-Object { $_.VolumeName -eq $path } | ForEach-Object { $_.InstallDate } | Sort-Object)
        $o.shadows = $dates.Count
        if ($dates.Count) { $o.newest = ([DateTimeOffset]$dates[-1]).ToUnixTimeSeconds() }
      } catch { }
      try { $o.cfa = [int](Get-MpPreference).EnableControlledFolderAccess } catch { }
      Out $o
    }
    'selfheal' {
      if (-not $L) { Out @{ ok = $false; error = 'This drive has no letter.' }; exit }
      $t = Tool $fsutil @('repair', 'set', "$($L):", '1')
      if ($t.code -ne 0) { Out @{ ok = $false; error = $t.text }; exit }
      Out @{ ok = $true }
    }
    'permfix' {
      $steps = @(
        @($root, '/remove:d', '*S-1-5-18', '*S-1-5-32-544', '/C', '/Q'),
        @($root, '/grant', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '/C', '/Q'),
        @($root, '/remove:g', '*S-1-1-0', '*S-1-5-32-546', '*S-1-5-7', '/C', '/Q'))
      foreach ($s in $steps) {
        $t = Tool $icacls $s
        if ($t.code -ne 0) { Out @{ ok = $false; error = $t.text }; exit }
      }
      Out @{ ok = $true }
    }
    'shadow' {
      $r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = $root; Context = 'ClientAccessible' }
      if ($r.ReturnValue -ne 0) { Out @{ ok = $false; error = "Windows could not make a restore copy (code $($r.ReturnValue)). The drive may be too full, or the Volume Shadow Copy service is off." }; exit }
      Out @{ ok = $true }
    }
    'cfa' {
      Set-MpPreference -EnableControlledFolderAccess Enabled
      Out @{ ok = $true }
    }
    default { Out @{ ok = $false; error = 'Unknown action.' } }
  }
} catch {
  Out @{ ok = $false; error = [string]$_.Exception.Message }
}
