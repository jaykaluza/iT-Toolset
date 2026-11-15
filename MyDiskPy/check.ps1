# My Disk: look for file system errors on one drive, or fix them. Needs Administrator rights.
#   MD_ACTION=scan     Repair-Volume -Scan: an online check. Changes nothing; the drive stays in use.
#   MD_ACTION=fix      Repair-Volume -OfflineScanAndFix: takes the drive offline for a moment and repairs it (not for the Windows drive).
#   MD_ACTION=atboot   marks the drive so Windows checks and repairs it at the next restart (for the Windows drive, which can't go offline).
#   MD_ACTION=threats  lists what Microsoft Defender found since MD_SINCE; MD_ACTION=remove removes it (Remove-MpThreat) and lists again.
#   MD_ACTION=offline  restarts the PC into Microsoft Defender Offline, a rootkit and virus scan that runs before Windows loads.
# The drive is named by its volume path (\\?\Volume{...}\), which stays the same whatever letter it has. Values arrive only as environment variables.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Out($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 5)) }
function Threats {
  # What Microsoft Defender found since the scan started (MD_SINCE, Unix seconds), with each threat's name, severity and files.
  $since = [DateTimeOffset]::FromUnixTimeSeconds([int64]$env:MD_SINCE).LocalDateTime.AddMinutes(-1)
  $known = @{}; Get-MpThreat | ForEach-Object { $known[[string]$_.ThreatID] = $_ }
  @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $since } | Sort-Object InitialDetectionTime | ForEach-Object {
    $t = $known[[string]$_.ThreatID]
    @{ name = [string]$t.ThreatName; severity = [int]$t.SeverityID; status = [int]$_.ThreatStatusID; active = [bool]$t.IsActive
       files = @($_.Resources | Select-Object -First 5 | ForEach-Object { [string]$_ -replace '^[a-zA-Z]+:_', '' }) } } | Select-Object -First 20)
}
try {
  $path = [string]$env:MD_VOLUME
  if ($path -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') { Out @{ ok = $false; error = 'Not a volume path.' }; exit }
  $v = Get-Volume -Path $path
  if (-not $v) { Out @{ ok = $false; error = 'That drive is gone.' }; exit }
  switch ($env:MD_ACTION) {
    'scan'   { $r = Repair-Volume -Path $path -Scan; Out @{ ok = $true; result = [string]$r } }
    'fix'    { $r = Repair-Volume -Path $path -OfflineScanAndFix; Out @{ ok = $true; result = [string]$r } }
    'atboot' {
      if (-not $v.DriveLetter) { Out @{ ok = $false; error = 'This drive has no letter.' }; exit }
      $out = & "$env:SystemRoot\System32\fsutil.exe" dirty set "$($v.DriveLetter):" 2>&1
      if ($LASTEXITCODE -ne 0) { Out @{ ok = $false; error = (($out | Out-String).Trim()) }; exit }
      Out @{ ok = $true; result = 'ScheduledAtRestart' }
    }
    'threats' { Out @{ ok = $true; threats = @(Threats) } }
    'remove'  { Remove-MpThreat; Start-Sleep 2; Out @{ ok = $true; result = 'removed'; threats = @(Threats) } }
    'offline' {
      # Microsoft Defender Offline: Windows restarts about a minute later and scans for rootkits before it loads (about 15 minutes).
      Start-MpWDOScan
      Out @{ ok = $true; result = 'scheduled' }
    }
    default  { Out @{ ok = $false; error = 'Unknown action.' } }
  }
} catch {
  Out @{ ok = $false; error = [string]$_.Exception.Message }
}
