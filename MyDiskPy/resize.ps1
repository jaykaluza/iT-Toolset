# My Disk: the size limits of one partition (MD_ACTION=info), or resize it (MD_ACTION=resize, to MD_SIZE bytes).
# The partition is named by disk number and partition number, and only touched if that disk still has the same unique ID
# and the partition still starts at the same place, so a drive plugged in or out meanwhile can't put the wrong one in its place.
# All values arrive as environment variables, never inside the script text. Needs Administrator rights.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Out($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress)) }
try {
  $disk = [int]$env:MD_DISK; $part = [int]$env:MD_PART; $offset = [int64]$env:MD_OFFSET
  $d = Get-Disk -Number $disk
  if ([string]$d.UniqueId -ne $env:MD_UNIQUE) { Out @{ ok = $false; error = 'The disks changed since the page was drawn. Refresh and try again.' }; exit }
  $p = Get-Partition -DiskNumber $disk -PartitionNumber $part
  if ([int64]$p.Offset -ne $offset) { Out @{ ok = $false; error = 'The partition moved since the page was drawn. Refresh and try again.' }; exit }
  $s = Get-PartitionSupportedSize -DiskNumber $disk -PartitionNumber $part
  if ($env:MD_ACTION -eq 'info') { Out @{ ok = $true; size = [int64]$p.Size; min = [int64]$s.SizeMin; max = [int64]$s.SizeMax }; exit }
  if ($env:MD_ACTION -ne 'resize') { Out @{ ok = $false; error = 'Unknown action.' }; exit }
  $size = [int64]$env:MD_SIZE
  if ($size -lt [int64]$s.SizeMin -or $size -gt [int64]$s.SizeMax) { Out @{ ok = $false; error = 'That size is outside what Windows allows for this partition right now.' }; exit }
  if ($size -eq [int64]$p.Size) { Out @{ ok = $true; size = $size; unchanged = $true }; exit }
  Resize-Partition -DiskNumber $disk -PartitionNumber $part -Size $size
  $after = Get-Partition -DiskNumber $disk -PartitionNumber $part
  Out @{ ok = $true; size = [int64]$after.Size }
} catch {
  Out @{ ok = $false; error = [string]$_.Exception.Message }
}
