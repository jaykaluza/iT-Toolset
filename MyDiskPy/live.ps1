# My Disk: every 2 seconds, the disks' raw activity counters and how much room each drive has left, as one JSON line.
# The app turns two readings into speeds. Stops by itself when My Disk (process id in MD_PARENT) is gone.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$parent = [int]$env:MD_PARENT
while ($true) {
  if (-not (Get-Process -Id $parent)) { exit }
  $p = @(Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk | Where-Object Name -ne '_Total' | ForEach-Object {
    [ordered]@{ Name = [string]$_.Name; Read = [uint64]$_.DiskReadBytesPersec; Write = [uint64]$_.DiskWriteBytesPersec; Reads = [uint64]$_.DiskReadsPersec; Writes = [uint64]$_.DiskWritesPersec
      Idle = [uint64]$_.PercentIdleTime; Time = [uint64]$_.Timestamp_Sys100NS; Queue = [int]$_.CurrentDiskQueueLength
      Wait = [uint64]$_.AvgDisksecPerTransfer; WaitBase = [uint64]$_.AvgDisksecPerTransfer_Base; Freq = [uint64]$_.Frequency_PerfTime } })
  $l = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [ordered]@{ Letter = $_.DeviceID.TrimEnd(':'); Free = [int64]$_.FreeSpace } })
  [Console]::Out.WriteLine(([ordered]@{ disks = $p; free = $l } | ConvertTo-Json -Depth 4 -Compress))
  [Console]::Out.Flush()
  Start-Sleep -Seconds 2
}
