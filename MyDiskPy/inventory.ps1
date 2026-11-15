# My Disk: everything Windows reports about this PC's disks, as one JSON object. Read-only; changes nothing.
# Temperature, wear, power-on hours and BitLocker details need Administrator rights; without them those parts are empty.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
function S($v) { if ($null -eq $v) { $null } else { [string]$v } }
$o = [ordered]@{ admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

$o.physical = @(Get-PhysicalDisk | ForEach-Object {
  $r = $null
  if ($o.admin) { $r = $_ | Get-StorageReliabilityCounter }
  [ordered]@{ Id = S $_.DeviceId; Name = S $_.FriendlyName; Maker = S $_.Manufacturer; Model = S $_.Model; Media = S $_.MediaType; Bus = S $_.BusType
    Size = [int64]$_.Size; Health = S $_.HealthStatus; Status = @($_.OperationalStatus | ForEach-Object { S $_ }); Serial = S $_.SerialNumber; Firmware = S $_.FirmwareVersion
    Spindle = $_.SpindleSpeed; LogicalSector = $_.LogicalSectorSize; PhysicalSector = $_.PhysicalSectorSize; Usage = S $_.Usage; CanPool = $_.CanPool
    Rel = $(if ($r) { [ordered]@{ Temp = $r.Temperature; TempMax = $r.TemperatureMax; Wear = $r.Wear; Hours = $r.PowerOnHours; ReadErrors = $r.ReadErrorsTotal
      ReadFixed = $r.ReadErrorsCorrected; ReadUnfixed = $r.ReadErrorsUncorrected; WriteErrors = $r.WriteErrorsTotal; WriteUnfixed = $r.WriteErrorsUncorrected
      Starts = $r.StartStopCycleCount; LoadCycles = $r.LoadUnloadCycleCount; ReadLatencyMax = $r.ReadLatencyMax; WriteLatencyMax = $r.WriteLatencyMax; FlushLatencyMax = $r.FlushLatencyMax } } else { $null }) } })

$o.disks = @(Get-Disk | ForEach-Object { [ordered]@{ Number = $_.Number; Style = S $_.PartitionStyle; Boot = $_.IsBoot; System = $_.IsSystem; Offline = $_.IsOffline
  ReadOnly = $_.IsReadOnly; Location = S $_.Location; UniqueId = S $_.UniqueId; Guid = S $_.Guid; Signature = $_.Signature; Allocated = [int64]$_.AllocatedSize
  LargestFree = [int64]$_.LargestFreeExtent; Partitions = $_.NumberOfPartitions; OfflineReason = S $_.OfflineReason; Provisioning = S $_.ProvisioningType; Bus = S $_.BusType } })

$o.partitions = @(Get-Partition | ForEach-Object { [ordered]@{ Disk = $_.DiskNumber; Number = $_.PartitionNumber; Letter = S $_.DriveLetter; Type = S $_.Type
  Gpt = S $_.GptType; Mbr = $_.MbrType; Size = [int64]$_.Size; Offset = [int64]$_.Offset; Active = $_.IsActive; Hidden = $_.IsHidden; Boot = $_.IsBoot; System = $_.IsSystem
  ReadOnly = $_.IsReadOnly; NoLetter = $_.NoDefaultDriveLetter; Paths = @($_.AccessPaths | ForEach-Object { S $_ }) } })

$wv = @{}
Get-CimInstance Win32_Volume | ForEach-Object { $wv[$_.DeviceID] = $_ }
$o.volumes = @(Get-Volume | ForEach-Object {
  $w = $wv[$_.Path]
  [ordered]@{ Path = S $_.Path; Letter = S $_.DriveLetter; Label = S $_.FileSystemLabel; FileSystem = S $_.FileSystem; DriveType = S $_.DriveType; Health = S $_.HealthStatus
    Status = S $_.OperationalStatus; Size = [int64]$_.Size; Free = [int64]$_.SizeRemaining; Cluster = $_.AllocationUnitSize; Dedup = S $_.DedupMode
    Indexing = $w.IndexingEnabled; Dirty = $w.DirtyBitSet; BootVolume = $w.BootVolume; SystemVolume = $w.SystemVolume; PageFile = $w.PageFilePresent
    VolumeSerial = $(if ($w.SerialNumber) { '{0:X8}' -f [uint32]$w.SerialNumber } else { $null }); Compressed = $w.Compressed; Quotas = $w.QuotasEnabled } })

$shell = New-Object -ComObject Shell.Application
$o.bitlocker = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  $d = $_.DeviceID
  [ordered]@{ Letter = $d.TrimEnd(':'); Shell = $shell.NameSpace("$d\").Self.ExtendedProperty('System.Volume.BitLockerProtection') } })
if ($o.admin) {
  $o.bitlockerAdmin = @(Get-BitLockerVolume | ForEach-Object { [ordered]@{ Mount = S $_.MountPoint; Status = S $_.VolumeStatus; Protection = S $_.ProtectionStatus
    Lock = S $_.LockStatus; Percent = $_.EncryptionPercentage; Method = S $_.EncryptionMethod; Keys = @($_.KeyProtector | ForEach-Object { S $_.KeyProtectorType }) } })
}

$o.drives = @(Get-CimInstance Win32_DiskDrive | ForEach-Object { [ordered]@{ Index = $_.Index; Model = S $_.Model; Interface = S $_.InterfaceType; Pnp = S $_.PNPDeviceID
  MediaType = S $_.MediaType; Status = S $_.Status; ScsiPort = $_.SCSIPort; ScsiTarget = $_.SCSITargetId } })
$o.other = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType<>3' | ForEach-Object { [ordered]@{ Letter = $_.DeviceID.TrimEnd(':'); Type = $_.DriveType
  Label = S $_.VolumeName; FileSystem = S $_.FileSystem; Size = $_.Size; Free = $_.FreeSpace; Provider = S $_.ProviderName } })
$o.pagefiles = @(Get-CimInstance Win32_PageFileUsage | ForEach-Object { [ordered]@{ Path = S $_.Name; SizeMB = $_.AllocatedBaseSize; UsedMB = $_.CurrentUsage; PeakMB = $_.PeakUsage } })
$o.trim = S ((& "$env:SystemRoot\System32\fsutil.exe" behavior query DisableDeleteNotify) -join "`n")
$o.systemDrive = $env:SystemDrive
# Antivirus: whether Microsoft Defender can scan on request (Normal or passive mode can; "Not running" can't), and which antivirus is on.
$o.defender = S (Get-MpComputerStatus).AMRunningMode
$o.antivirus = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Where-Object { ($_.productState -band 0x1000) -ne 0 } | ForEach-Object { S $_.displayName })
$o | ConvertTo-Json -Depth 6 -Compress
