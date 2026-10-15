<#
.SYNOPSIS
  Live Windows connectivity monitor. Maps every TCP connection to its owning app,
  flags external (public internet) peers, classifies inbound vs outbound, lists
  listening ports, and serves it all as an auto-refreshing HTML dashboard.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\NetMonitor.ps1
  Run from an elevated (Administrator) prompt to see paths/descriptions for every process.

.EXAMPLE
  .\NetMonitor.ps1 -IntervalSeconds 5 -NoBrowser
#>
param(
  [int]$IntervalSeconds = 3,
  [string]$OutDir = (Join-Path $PSScriptRoot 'NetMonitorOutput'),
  [int]$ClosedRetentionMinutes = 10,
  [switch]$NoBrowser,
  [switch]$Once
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$htmlPath = Join-Path $OutDir 'dashboard.html'
$dataPath = Join-Path $OutDir 'data.js'
$csvPath  = Join-Path $OutDir ('connections-{0:yyyyMMdd}.csv' -f (Get-Date))
$utf8     = New-Object System.Text.UTF8Encoding($false)
$isAdmin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
              [Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------- helpers

function Test-ExternalIP([string]$ip) {
  $addr = $null
  if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$addr)) { return $false }
  if ($addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() }
  $b = $addr.GetAddressBytes()
  if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }                    # link-local
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }  # CGNAT
    return $true
  }
  if ([System.Net.IPAddress]::IsLoopback($addr) -or $addr.Equals([System.Net.IPAddress]::IPv6Any)) { return $false }
  if ($addr.IsIPv6LinkLocal -or $addr.IsIPv6SiteLocal -or $addr.IsIPv6Multicast) { return $false }
  if (($b[0] -band 0xFE) -eq 0xFC) { return $false }                           # fc00::/7 ULA
  return $true
}

$procCache = @{}
function Get-ProcInfo([int]$procId) {
  if ($procCache.ContainsKey($procId)) { return $procCache[$procId] }
  $info = [pscustomobject]@{ Name = "PID $procId"; Path = ''; Description = ''; Signature = ''; Publisher = '';
                             Company = ''; Product = ''; Origin = '' }
  if ($procId -eq 0) { $info.Name = 'System Idle' }
  elseif ($procId -eq 4) { $info.Name = 'System'; $info.Description = 'Windows kernel' }
  else {
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($p) {
      $info.Name = $p.ProcessName
      try { if ($p.Path) { $info.Path = $p.Path } } catch {}
    }
    # services report their executable even when the process itself is hidden from non-admins
    if (-not $info.Path -and $svcPathMap.ContainsKey($procId)) { $info.Path = $svcPathMap[$procId] }
  }
  if ($info.Path) {
    try {
      $v = [Diagnostics.FileVersionInfo]::GetVersionInfo($info.Path)
      $info.Description = [string]$v.FileDescription; $info.Company = [string]$v.CompanyName; $info.Product = [string]$v.ProductName
    } catch {}
  }
  $sig = Get-FileSignature $info.Path
  if ($sig) { $info.Signature = $sig.Status; $info.Publisher = $sig.Publisher }
  $info.Origin = Get-Origin $info
  $procCache[$procId] = $info
  $info
}

# windows = part of Windows itself; microsoft = Microsoft app installed on top; thirdparty = signed by another
# company; unsigned = no valid signature; unknown = location hidden (run as Administrator)
function Get-Origin($pi) {
  if ($pi.Path) {
    $inWindows = $pi.Path.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)
    if ($pi.Signature -in @('NotSigned', 'HashMismatch', 'NotTrusted')) { return 'unsigned' }
    if ($pi.Signature -ne 'Valid') {
      if ($inWindows -and $pi.Company -like 'Microsoft*') { return 'windows' }
      return 'unknown'
    }
    # drivers from other vendors (Intel, Realtek...) are countersigned by Microsoft's hardware program
    if ($pi.Publisher -like '*Hardware Compatibility*') { return 'thirdparty' }
    if ($pi.Publisher -like 'Microsoft Windows*' -or ($inWindows -and $pi.Publisher -like 'Microsoft*')) { return 'windows' }
    if ($pi.Publisher -like 'Microsoft*') { return 'microsoft' }
    return 'thirdparty'
  }
  if ($coreProcs -contains $pi.Name) { return 'windows' }
  'unknown'
}

$sigCache = @{}
function Get-FileSignature([string]$path) {
  if (-not $path) { return $null }
  if ($sigCache.ContainsKey($path)) { return $sigCache[$path] }
  $res = [pscustomobject]@{ Status = 'Unknown'; Publisher = '' }
  try {
    $s = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    $res.Status = [string]$s.Status
    if ($s.SignerCertificate) { $res.Publisher = $s.SignerCertificate.Subject -replace '^CN="?([^",]+).*', '$1' }
  } catch {}
  $sigCache[$path] = $res
  $res
}

# ---------------------------------------------------------------- risk rules

$scriptHosts = @('powershell', 'pwsh', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32',
                 'certutil', 'bitsadmin', 'msbuild', 'installutil')
$coreProcs   = @('System', 'System Idle', 'Registry', 'Secure System', 'smss', 'csrss', 'wininit', 'services',
                 'lsass', 'svchost', 'MemCompression', 'LsaIso')
$lookalikeNames = @('svchost', 'lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'spoolsv', 'taskhostw',
                    'dllhost', 'conhost', 'runtimebroker', 'rundll32', 'explorer', 'searchindexer', 'lsm')
$badPorts    = @{ 4444 = 'the default port of the Metasploit hacking tool'; 1337 = 'a classic backdoor port';
                  31337 = 'a classic backdoor port'; 12345 = 'the NetBus trojan port'; 6666 = 'IRC, used by botnets';
                  6667 = 'IRC, used by botnets'; 6697 = 'IRC, used by botnets'; 9001 = 'the Tor network';
                  9030 = 'the Tor network'; 9050 = 'the Tor network' }
$exposedPortRisk = @{
  3389 = @('high',   'Remote Desktop is ON and your firewall allows it, so anyone on your network can try to log in to this PC. Fix (if you don''t use it): Settings > System > Remote Desktop > turn it Off.')
  5900 = @('high',   'A VNC remote-control server is listening. Fix: if you didn''t install remote-control software on purpose, uninstall it from Settings > Apps > Installed apps.')
  23   = @('high',   'A Telnet server is listening (unencrypted remote login). Fix: Control Panel > Programs > Turn Windows features on or off > untick "Telnet Server", or uninstall the app that opened it.')
  21   = @('medium', 'An FTP server is listening (passwords travel unencrypted). Fix: stop or uninstall the FTP app if you don''t need it.')
  22   = @('medium', 'An SSH server is listening for remote logins. Fix: if you didn''t set this up, Settings > System > Optional features > uninstall "OpenSSH Server".')
}
$onPublicNetwork = $false
try { $onPublicNetwork = @(Get-NetConnectionProfile -ErrorAction Stop | Where-Object NetworkCategory -eq 'Public').Count -gt 0 } catch {}

function New-Issue([string]$level, [string]$text) { [pscustomobject]@{ Level = $level; Text = $text } }

function Get-AppIssues($pi) {
  $issues = @()
  $p = $pi.Path
  if ($p) {
    if ($p -match '\\(AppData\\Local\\Temp|Windows\\Temp|Temp)\\|\\Downloads\\|\\Users\\Public\\|\$Recycle\.Bin') {
      $issues += New-Issue 'high' "Runs from an unusual folder ($p). Real programs live in Program Files or Windows. Fix: in File Explorer right-click the file > 'Scan with Microsoft Defender'. If you don't recognise it, end it in Task Manager and delete or uninstall it."
    }
    if ($lookalikeNames -contains $pi.Name.ToLower() -and -not $p.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)) {
      $issues += New-Issue 'high' "Uses the name of a Windows system file ($($pi.Name).exe) but runs from outside the Windows folder ($p). This is a common malware disguise. Fix: run a full Defender scan (Windows Security > Virus & threat protection > Scan options > Full scan) and a Microsoft Defender Offline scan."
    }
    if ($pi.Signature -eq 'HashMismatch') {
      $issues += New-Issue 'high' "The file's digital signature is broken, so it may have been tampered with. Fix: run a full scan (Windows Security > Virus & threat protection > Scan options > Full scan), then reinstall the app from its official website."
    } elseif ($pi.Signature -in @('NotSigned', 'NotTrusted', 'UnknownError')) {
      $issues += New-Issue 'medium' "Not signed by a known publisher. Not always bad (small and open-source tools often aren't), but most malware isn't signed. Fix: if you don't recognise '$($pi.Name)', scan it with Microsoft Defender and uninstall it from Settings > Apps."
    }
  } elseif ($isAdmin -and $coreProcs -notcontains $pi.Name) {
    $issues += New-Issue 'medium' "Windows won't reveal where this program lives, even to an Administrator. Fix: Task Manager > Details > right-click '$($pi.Name)' > Open file location, then scan that file with Microsoft Defender."
  }
  if ($scriptHosts -contains $pi.Name.ToLower()) {
    $issues += New-Issue 'medium' "A Windows scripting tool ($($pi.Name)) is using the network. That's fine if you just ran a script yourself (Claude uses PowerShell too); attackers also abuse these. Fix: Task Manager > Details > right-click a column header > Select columns > 'Command line' to see what it runs. End it if you didn't start it, then run a full Defender scan."
  }
  $issues
}

function Get-RiskLevel($issues) {
  if (@($issues | Where-Object Level -eq 'high').Count) { 'high' } elseif (@($issues).Count) { 'medium' } else { '' }
}

$svcMap = @{}
$svcPathMap = @{}
$svcInfo = @{}
$svcRefreshed = [datetime]::MinValue
function Update-ServiceMap {
  $script:svcMap = @{}; $script:svcPathMap = @{}; $script:svcInfo = @{}
  try {
    $all = @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction Stop)
    $all | Group-Object ProcessId | ForEach-Object {
      $script:svcMap[[int]$_.Name] = ($_.Group.Name | Sort-Object) -join ', '
      $exe = [string]$_.Group[0].PathName
      if ($exe -match '^"([^"]+)"') { $exe = $Matches[1] } elseif ($exe -match '^(.+?\.exe)\b') { $exe = $Matches[1] }
      $exe = [Environment]::ExpandEnvironmentVariables($exe)
      if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { $script:svcPathMap[[int]$_.Name] = $exe }
    }
    foreach ($s in $all) {
      $desc = [string]$s.Description
      if ($desc.StartsWith('@')) { $desc = '' }   # unresolved resource string
      if ($desc.Length -gt 220) { $desc = $desc.Substring(0, 217) + '...' }
      $script:svcInfo[$s.Name] = [pscustomobject]@{ d = [string]$s.DisplayName; s = $desc }
    }
  } catch {}
  $script:svcRefreshed = Get-Date
}

function Get-AdapterBytes {
  try {
    $s = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up' | Get-NetAdapterStatistics -ErrorAction Stop
    [pscustomobject]@{
      Rx = [double](($s | Measure-Object ReceivedBytes -Sum).Sum)
      Tx = [double](($s | Measure-Object SentBytes -Sum).Sum)
    }
  } catch { $null }
}

# ---------------------------------------------------------------- dashboard page

$html = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Monitor</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--text:#1b1f24;--muted:#646d78;--line:#e2e5e9;--accent:#2f6fde;
  --in:#c2410c;--in-bg:#fff1e8;--out:#1d6fd6;--out-bg:#e8f1fd;--ext:#7c3aed;--ext-bg:#f1eafe;--lan:#4b5563;--lan-bg:#eef0f2;
  --risk:#d61f1f;--risk-bg:#fde8e8;--caution:#a16207;--caution-bg:#fef6e0}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--panel:#191d23;--text:#e6e9ed;--muted:#8d96a1;--line:#2a3038;--accent:#6aa0ff;
  --in:#fb923c;--in-bg:#3a2214;--out:#6aa8ff;--out-bg:#16263d;--ext:#b794ff;--ext-bg:#2a1f45;--lan:#a3acb7;--lan-bg:#232830;
  --risk:#ff5c5c;--risk-bg:#3d1717;--caution:#f5b942;--caution-bg:#332811}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
header{padding:18px 20px 8px;display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 16px}
h1{font-size:20px;margin:0;font-weight:600}
.sub{color:var(--muted);font-size:13px}
.warn{color:var(--in)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;padding:8px 20px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.stat b{display:block;font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}
.stat span{color:var(--muted);font-size:12px}
.bar{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;padding:12px 20px}
.tabs{display:flex;gap:4px;background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:3px}
.tabs button{border:0;background:none;color:var(--muted);padding:6px 12px;border-radius:6px;font:inherit;cursor:pointer}
.tabs button.on{background:var(--accent);color:#fff}
input[type=search],select{font:inherit;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:6px 9px}
input[type=search]{min-width:220px}
label{color:var(--muted);display:flex;gap:5px;align-items:center;cursor:pointer}
.wrap{padding:0 20px 30px;overflow-x:auto}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;cursor:pointer;user-select:none;position:sticky;top:0;background:var(--panel)}
th.sorted::after{content:" ▾"}th.sorted.asc::after{content:" ▴"}
tr:last-child td{border-bottom:0}
tr.closed td{opacity:.45}
td.num{font-variant-numeric:tabular-nums}
.app{font-weight:600}
.small{color:var(--muted);font-size:12px;max-width:420px;overflow:hidden;text-overflow:ellipsis;display:block}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.in{color:var(--in);background:var(--in-bg)}.out{color:var(--out);background:var(--out-bg)}
.ext{color:var(--ext);background:var(--ext-bg)}.lan{color:var(--lan);background:var(--lan-bg)}
a.link{color:var(--accent);cursor:pointer;text-decoration:none}
.empty{padding:30px;text-align:center;color:var(--muted)}
tr.risk-high td{background:var(--risk-bg)}
tr.risk-high .app,tr.risk-high td:first-child{color:var(--risk)}
tr.risk-medium td{background:var(--caution-bg)}
tr[data-tip]{cursor:help}
.risk{color:#fff;background:var(--risk)}.caution{color:var(--caution);background:var(--caution-bg);border:1px solid var(--caution)}
.ok{color:var(--muted)}
.stat.alert{border-color:var(--risk);background:var(--risk-bg)}.stat.alert b{color:var(--risk)}
#tip{position:fixed;z-index:10;max-width:440px;background:var(--panel);color:var(--text);border:1px solid var(--line);
  border-left:4px solid var(--risk);border-radius:8px;padding:10px 12px;box-shadow:0 8px 24px rgba(0,0,0,.25);
  font-size:13px;pointer-events:none;display:none;white-space:normal}
#tip.medium{border-left-color:var(--caution)}
#tip h4{margin:0 0 6px;font-size:13px}
#tip p{margin:0 0 8px}#tip p:last-child{margin:0}
#tip .lvl{font-weight:700;color:var(--risk)}#tip .lvl.medium{color:var(--caution)}
[data-ai]{cursor:help;text-decoration:underline dotted var(--muted);text-underline-offset:3px}
#ainfo{position:fixed;z-index:11;width:440px;max-width:calc(100vw - 16px);background:var(--panel);color:var(--text);
  border:1px solid var(--line);border-radius:10px;padding:12px 14px;box-shadow:0 10px 30px rgba(0,0,0,.3);font-size:13px;display:none;white-space:normal}
#ainfo h4{margin:0 0 6px;font-size:15px}
#ainfo .sec{margin-top:9px}
#ainfo .sec b{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:2px}
#ainfo .path{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:var(--muted)}
#ainfo ul{margin:2px 0 0;padding-left:18px}
#ainfo .links a{color:var(--accent);margin-right:14px;text-decoration:none}
#ainfo .links a:hover{text-decoration:underline}
.origin{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600}
.o-windows{color:var(--out);background:var(--out-bg)}.o-microsoft{color:var(--ext);background:var(--ext-bg)}
.o-thirdparty{color:var(--lan);background:var(--lan-bg)}.o-unsigned{color:#fff;background:var(--risk)}.o-unknown{color:var(--caution);background:var(--caution-bg)}
</style>
</head>
<body>
<header><h1>Network Monitor</h1><span class="sub" id="meta">Waiting for data… keep NetMonitor.ps1 running.</span></header>
<div class="stats" id="stats"></div>
<div class="bar">
  <div class="tabs" id="tabs">
    <button data-t="conn">Connections</button><button data-t="apps">By app</button><button data-t="listen">Listening</button>
  </div>
  <input type="search" id="q" placeholder="Filter app, host, IP, port…">
  <select id="dir"><option value="all">In + out</option><option value="Inbound">Inbound only</option><option value="Outbound">Outbound only</option></select>
  <label><input type="checkbox" id="ext"> External only</label>
  <label><input type="checkbox" id="closed"> Show recently closed</label>
  <label><input type="checkbox" id="risky"> Risky only</label>
</div>
<div class="wrap" id="view"></div>
<div id="tip"></div>
<div id="ainfo"></div>
<script>
// Plain-English guide to common processes: [kind, what it does, risks, official page]
// kind: w = built into Windows, m = Microsoft app (not core Windows), t = third-party
const KB = {
  'system': ['w','The Windows kernel. Handles drivers, disk and network at the lowest level; file sharing (ports 139/445) shows up under it.','Normal. Can\'t be removed. Unusual inbound traffic here usually means file sharing is on.'],
  'system idle': ['w','Placeholder for unused CPU time. Connections listed under it are ones that are just closing.','None.'],
  'registry': ['w','Holds the Windows registry in memory.','None.'],
  'svchost': ['w','Service Host. Runs Windows background services (listed below) such as updates, networking and notifications. Many copies are normal.','The most-imitated name in malware. The real one only lives in C:\\Windows\\System32.'],
  'lsass': ['w','Local Security Authority. Checks your sign-in and protects passwords and security tokens.','Attackers target it to steal passwords. Must be in C:\\Windows\\System32; any copy elsewhere is malware.'],
  'services': ['w','Service Control Manager. Starts and stops Windows services.','Normal. Must be in C:\\Windows\\System32.'],
  'wininit': ['w','Windows start-up process. Launches core services at boot.','Normal. Must be in C:\\Windows\\System32.'],
  'winlogon': ['w','Handles signing in, locking and Ctrl+Alt+Del.','Normal. Must be in C:\\Windows\\System32.'],
  'csrss': ['w','Client/Server Runtime. Core part of Windows that manages console windows and shutdown.','Normal. Must be in C:\\Windows\\System32.'],
  'smss': ['w','Session Manager. Starts your Windows session at boot.','Normal.'],
  'explorer': ['w','Your desktop, taskbar, Start menu and File Explorer.','Normal. Must be C:\\Windows\\explorer.exe.'],
  'spoolsv': ['w','Print Spooler. Sends documents to printers.','Has had serious security bugs (PrintNightmare). If you never print, you can disable the "Print Spooler" service.'],
  'dllhost': ['w','COM Surrogate. Runs helper code for other programs, e.g. making thumbnails.','Normal; sometimes imitated by malware.'],
  'conhost': ['w','Console Window Host. Draws command-line windows.','Normal.'],
  'taskhostw': ['w','Runs scheduled tasks and background jobs for Windows.','Normal.'],
  'runtimebroker': ['w','Checks permissions (camera, location…) for Store apps.','Normal.'],
  'backgroundtaskhost': ['w','Runs background tasks for Store apps, e.g. live tiles and sync.','Normal. Check which app it belongs to if it uses a lot of network.'],
  'sihost': ['w','Shell Infrastructure Host. Handles parts of the desktop like notifications.','Normal.'],
  'ctfmon': ['w','Text input (keyboard layouts, touch keyboard, handwriting).','Normal.'],
  'searchhost': ['w','Windows Search box. Fetches web results from Bing.','Normal. Sends what you type in Search to Bing; you can turn off web results in Settings > Privacy.'],
  'searchapp': ['w','Windows Search box. Fetches web results from Bing.','Normal.'],
  'searchindexer': ['w','Indexes your files so Search is fast.','Normal.'],
  'startmenuexperiencehost': ['w','The Start menu.','Normal.'],
  'shellexperiencehost': ['w','Draws taskbar pop-ups, clock and notification area.','Normal.'],
  'textinputhost': ['w','On-screen and emoji keyboard.','Normal.'],
  'widgets': ['w','The Widgets board (news, weather).','Normal. Downloads news content from Microsoft.'],
  'smartscreen': ['w','Microsoft Defender SmartScreen. Checks downloads and websites against a list of known threats.','Protective. Keep it on.'],
  'msmpeng': ['w','Microsoft Defender Antivirus engine.','Protective. Keep it on.'],
  'nissrv': ['w','Defender Network Inspection. Blocks network-based attacks.','Protective.'],
  'mpdefendercoreservice': ['w','Microsoft Defender core service.','Protective.'],
  'securityhealthservice': ['w','Windows Security app background service.','Protective.'],
  'mousocoreworker': ['w','Windows Update orchestrator. Checks for and downloads updates.','Normal. Keep updates on.'],
  'tiworker': ['w','Windows Modules Installer. Installs updates.','Normal.'],
  'wermgr': ['w','Windows Error Reporting. Sends crash reports to Microsoft.','Normal.'],
  'compattelrunner': ['w','Compatibility Telemetry. Sends usage/diagnostic data to Microsoft.','Privacy rather than security. Reduce it in Settings > Privacy > Diagnostics & feedback.'],
  'audiodg': ['w','Windows audio engine.','Normal.'],
  'dwm': ['w','Desktop Window Manager. Draws everything on screen.','Normal.'],
  'fontdrvhost': ['w','Font driver host.','Normal.'],
  'lsaiso': ['w','Credential Guard. Isolates passwords in a secure area.','Protective.'],
  'phoneexperiencehost': ['w','Phone Link. Connects your phone to the PC.','Normal if you use Phone Link; can be removed if not.'],
  'crossdeviceservice': ['w','Cross-device experiences (Phone Link, nearby sharing).','Normal.'],
  'msedge': ['w','Microsoft Edge, the web browser that ships with Windows 11.','Normal. Keep it updated; review extensions in edge://extensions.','https://www.microsoft.com/edge'],
  'msedgewebview2': ['w','Edge WebView2. Lets other apps (Teams, Widgets, Outlook…) show web pages.','Normal. Check which app launched it if traffic looks odd.'],
  'powershell': ['w','Windows PowerShell, the built-in scripting shell.','Fine when you or a trusted tool runs it; also a favourite of attackers. Check its command line in Task Manager.'],
  'cmd': ['w','Command Prompt.','Fine when you run it; abused by malware.'],
  'rundll32': ['w','Runs code stored in DLL files on behalf of Windows.','Often abused by malware. Network traffic from it deserves a look.'],
  'mshta': ['w','Runs HTML Application (.hta) files.','Rarely used legitimately today; heavily abused by malware.'],
  'wscript': ['w','Windows Script Host (VBScript/JScript).','Commonly abused by malicious email attachments.'],
  'cscript': ['w','Windows Script Host, command-line version.','Commonly abused by malware.'],
  'pwsh': ['m','PowerShell 7, Microsoft\'s modern scripting shell (installed separately).','Fine when you or a trusted tool runs it (Claude uses it); abused by attackers too.','https://learn.microsoft.com/powershell/'],
  'onedrive': ['m','OneDrive cloud storage sync.','Normal. It uploads your synced folders to Microsoft.','https://www.microsoft.com/microsoft-365/onedrive'],
  'ms-teams': ['m','Microsoft Teams chat and meetings.','Normal.','https://www.microsoft.com/microsoft-teams'],
  'teams': ['m','Microsoft Teams chat and meetings.','Normal.','https://www.microsoft.com/microsoft-teams'],
  'outlook': ['m','Microsoft Outlook email.','Normal. Be careful with attachments and links.','https://www.microsoft.com/microsoft-365/outlook'],
  'olk': ['m','New Outlook for Windows.','Normal.','https://www.microsoft.com/microsoft-365/outlook'],
  'code': ['m','Visual Studio Code editor.','Normal. Extensions can access the network; install only trusted ones.','https://code.visualstudio.com'],
  'chrome': ['t','Google Chrome web browser.','Normal. Keep it updated and review extensions at chrome://extensions.','https://www.google.com/chrome/'],
  'firefox': ['t','Mozilla Firefox web browser.','Normal. Keep it updated.','https://www.mozilla.org/firefox/'],
  'opera': ['t','Opera web browser.','Normal. Its built-in VPN/ads features make extra connections.','https://www.opera.com'],
  'brave': ['t','Brave web browser.','Normal.','https://brave.com'],
  'claude': ['t','Claude desktop app by Anthropic.','Normal. Talks to api.anthropic.com and claude.ai.','https://claude.ai/download'],
  'apsdaemon': ['t','Apple Push Service. Delivers iCloud notifications (part of iCloud for Windows).','Normal if you use iCloud.','https://support.apple.com/icloud'],
  'discord': ['t','Discord chat and voice.','Normal. Scammers send malicious files via Discord; don\'t run attachments from strangers.','https://discord.com'],
  'steam': ['t','Steam game store and launcher.','Normal.','https://store.steampowered.com'],
  'spotify': ['t','Spotify music streaming.','Normal.','https://www.spotify.com'],
  'zoom': ['t','Zoom video meetings.','Normal. Keep it updated.','https://zoom.us'],
  'slack': ['t','Slack team chat.','Normal.','https://slack.com'],
  'dropbox': ['t','Dropbox cloud storage sync.','Normal. It uploads your synced folders.','https://www.dropbox.com'],
  'googledrivefs': ['t','Google Drive for desktop.','Normal. It uploads your synced folders.','https://www.google.com/drive/download/'],
  'lms': ['t','Intel Local Manageability Service. Part of Intel Management Engine / AMT, installed by your PC maker for remote management.','Listens on ports 16992-16993 and 623/664. Low risk on home PCs but keep Intel ME/chipset drivers updated (Intel has had serious AMT flaws).','https://www.intel.com/content/www/us/en/support/articles/000005515.html'],
  'jhi_service': ['t','Intel Dynamic Application Loader host. Part of Intel Management Engine software from your PC maker.','Low risk. Keep Intel drivers updated.','https://www.intel.com/content/www/us/en/support.html'],
  'teamviewer': ['t','TeamViewer remote-control software.','HIGH if you didn\'t install it: tech-support scammers use it to take over PCs. Uninstall if you don\'t use it.','https://www.teamviewer.com'],
  'anydesk': ['t','AnyDesk remote-control software.','HIGH if you didn\'t install it: commonly used by scammers. Uninstall if you don\'t use it.','https://anydesk.com'],
  'wudfhost': ['w','User-Mode Driver Framework host. Runs device drivers (fingerprint readers, sensors, USB devices) safely outside the kernel.','Normal.'],
  'systemsettings': ['w','The Windows Settings app.','Normal.'],
  'onedrive.sync.service': ['m','OneDrive background sync service.','Normal. It uploads your synced folders to Microsoft.','https://www.microsoft.com/microsoft-365/onedrive'],
  'esrv': ['t','Intel Energy Server. Part of Intel driver/update software that collects power and usage data.','Low risk; sends telemetry to Intel. Can be removed via Settings > Apps (Intel Driver & Support Assistant) if unwanted.','https://www.intel.com/content/www/us/en/support/detect.html'],
  'esrv_svc': ['t','Intel Energy Server service (Intel driver/update software).','Low risk; telemetry to Intel.','https://www.intel.com/content/www/us/en/support/detect.html'],
  'ipfsvc': ['t','Intel Innovation Platform Framework. Manages power/thermal behaviour on Intel laptops; installed by your PC maker.','Low risk. Keep Intel drivers updated.','https://www.intel.com/content/www/us/en/support.html'],
  'nvcontainer': ['t','NVIDIA graphics driver helper (GeForce Experience / NVIDIA App).','Normal; checks for driver updates.','https://www.nvidia.com/drivers'],
};
const KB_PREFIX = [[/^icloud/, ['t','Part of iCloud for Windows: syncs Photos, Drive, passwords and other Apple data.','Normal if you use iCloud. Many connections to Apple (17.x.x.x addresses) are expected.','https://support.apple.com/icloud']]];
const kbFor = n => { const k = String(n || '').toLowerCase(); return KB[k] || (KB_PREFIX.find(p => p[0].test(k)) || [])[1]; };
const ORIGIN = {
  windows: ['Built into Windows', 'o-windows'], microsoft: ['Microsoft app (not core Windows)', 'o-microsoft'],
  thirdparty: ['Third-party app', 'o-thirdparty'], unsigned: ['Not digitally signed', 'o-unsigned'],
  unknown: ['Unknown (run as Administrator to check)', 'o-unknown']
};
const S = {tab:'conn', q:'', dir:'all', ext:true, closed:false, risky:false, sort:{conn:['rr',-1],apps:['rr',-1],listen:['rr',-1]}};
try { Object.assign(S, JSON.parse(localStorage.getItem('netmon') || '{}')); } catch(e) {}
const save = () => { try { localStorage.setItem('netmon', JSON.stringify(S)); } catch(e) {} };
const $ = s => document.querySelector(s);
const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const rate = b => b == null ? '—' : b < 1024 ? b.toFixed(0)+' B/s' : b < 1048576 ? (b/1024).toFixed(1)+' KB/s' : (b/1048576).toFixed(2)+' MB/s';
const dur = (a, b) => { let s = Math.max(0, (b - a) / 1000) | 0; if (s < 60) return s+'s'; if (s < 3600) return (s/60|0)+'m '+(s%60)+'s'; return (s/3600|0)+'h '+((s%3600)/60|0)+'m'; };
const appLabel = c => c.Services ? c.App + ' · ' + c.Services : (c.Description && c.Description.toLowerCase() !== c.App.toLowerCase() ? c.App + ' · ' + c.Description : c.App);

const RANK = {high:2, medium:1};
let TIPS = [];
// registers a tooltip for a row and returns the row attributes
function rowAttrs(risk, issues, who, extra) {
  const cls = [extra, risk ? 'risk-' + risk : ''].filter(Boolean).join(' ');
  let tip = '';
  if (risk) { TIPS.push({risk, issues: [].concat(issues || []), who}); tip = ` data-tip="${TIPS.length - 1}"`; }
  return ` class="${cls}"${tip}`;
}
const riskPill = r => r === 'high' ? '<span class="pill risk">⚠ Risky</span>' : r === 'medium' ? '<span class="pill caution">Check</span>' : '<span class="ok">OK</span>';

function filtered(d) {
  const q = S.q.trim().toLowerCase();
  return d.connections.filter(c =>
    (!S.risky || c.Risk) && (S.closed || !c.Closed) && (!S.ext || c.External) && (S.dir === 'all' || c.Direction === S.dir) &&
    (!q || [c.App, c.Description, c.Services, c.Path, c.RemoteHost, c.RemoteAddress, c.RemotePort, c.LocalPort, c.PID].join(' ').toLowerCase().includes(q)));
}

function sortRows(rows, key) {
  const [k, dir] = S.sort[key];
  return rows.sort((a, b) => { const x = a[k], y = b[k];
    return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x ?? '').localeCompare(String(y ?? ''), undefined, {numeric:true})) * dir; });
}

function table(cols, rows, key) {
  if (!rows.length) return '<div class="empty">Nothing matches the current filters.</div>';
  const [sk, sd] = S.sort[key];
  return '<table><thead><tr>' + cols.map(c => `<th data-k="${c[0]}" data-key="${key}" class="${c[0]===sk?'sorted'+(sd>0?' asc':''):''}">${c[1]}</th>`).join('') +
    '</tr></thead><tbody>' + rows.join('') + '</tbody></table>';
}

function render() {
  const d = window.NETDATA; if (!d) return;
  const now = new Date(d.generated);
  const active = d.connections.filter(c => !c.Closed), ext = active.filter(c => c.External);
  $('#meta').innerHTML = `${esc(d.host)} · updated ${now.toLocaleTimeString()} · every ${d.interval}s` +
    (d.admin ? '' : ' · <span class="warn">not elevated: some app paths hidden — run as Administrator for full detail</span>');
  TIPS = [];
  const riskyApps = new Set([...active.filter(c => c.Risk === 'high'), ...d.listeners.filter(l => l.Risk === 'high')].map(x => x.App));
  const st = [[riskyApps.size,'Risky apps (red)', riskyApps.size ? 'alert' : ''],[active.length,'Active connections'],[ext.length,'External'],[ext.filter(c=>c.Direction==='Inbound').length,'External inbound'],
    [ext.filter(c=>c.Direction==='Outbound').length,'External outbound'],[new Set(ext.map(c=>c.App)).size,'Apps talking out'],
    [rate(d.rxRate),'Download (all apps)'],[rate(d.txRate),'Upload (all apps)']];
  $('#stats').innerHTML = st.map(s => `<div class="stat ${s[2] || ''}"><b>${s[0]}</b><span>${s[1]}</span></div>`).join('');
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.t === S.tab));
  $('#dir').disabled = $('#closed').disabled = S.tab === 'listen'; $('#ext').disabled = S.tab === 'listen';

  let out = '';
  if (S.tab === 'conn') {
    const rows = sortRows(filtered(d).map(c => ({...c, rr: RANK[c.Risk] || 0, Dur: (c.Closed ? new Date(c.Closed) : now) - new Date(c.FirstSeen)})), 'conn').map(c =>
      `<tr${rowAttrs(c.Risk, c.Issues, c.App, c.Closed ? 'closed' : '')}><td>${riskPill(c.Risk)}</td><td><span class="pill ${c.Direction==='Inbound'?'in':'out'}">${c.Direction==='Inbound'?'↓ In':'↑ Out'}</span></td>
      <td><span class="app" data-ai="${esc(c.App)}" data-svc="${esc(c.Services)}">${esc(appLabel(c))}</span><span class="small" title="${esc(c.Path)}">${esc(c.Path)}</span></td><td class="num">${c.PID}</td>
      <td>${esc(c.RemoteHost || '—')}</td><td class="num">${esc(c.RemoteAddress)}</td><td class="num">${c.RemotePort}</td><td class="num">${c.LocalPort}</td>
      <td><span class="pill ${c.External?'ext':'lan'}">${c.External?'Internet':'Local'}</span></td><td>${c.Closed?'Closed':esc(c.State)}</td><td class="num">${dur(0, c.Dur)}</td></tr>`);
    out = table([['rr','Risk'],['Direction','Dir'],['App','App'],['PID','PID'],['RemoteHost','Remote host'],['RemoteAddress','Remote IP'],['RemotePort','Port'],
      ['LocalPort','Local port'],['External','Scope'],['State','State'],['Dur','Age']], rows, 'conn');
  } else if (S.tab === 'apps') {
    const g = {};
    filtered(d).forEach(c => { const a = g[c.App] ||= {App:c.App, label:appLabel(c), Path:c.Path, pids:new Set(), total:0, ext:0, extIn:0, extOut:0, hosts:new Set(), rr:0, issues:new Map(), svc:new Set()};
      a.pids.add(c.PID); a.total++; if (c.External) { a.ext++; c.Direction==='Inbound' ? a.extIn++ : a.extOut++; } a.hosts.add(c.RemoteHost || c.RemoteAddress); if (!a.Path) a.Path = c.Path;
      a.rr = Math.max(a.rr, RANK[c.Risk] || 0); if (c.Services) c.Services.split(', ').forEach(s => a.svc.add(s)); [].concat(c.Issues || []).forEach(i => a.issues.set(i.Text, i)); });
    const rows = sortRows(Object.values(g).map(a => ({...a, nhosts:a.hosts.size})), 'apps').map(a => { const r = ['', 'medium', 'high'][a.rr]; return (
      `<tr${rowAttrs(r, [...a.issues.values()], a.App)}><td>${riskPill(r)}</td><td><a class="link app" data-app="${esc(a.App)}" data-ai="${esc(a.App)}" data-svc="${esc([...a.svc].join(', '))}">${esc(a.label)}</a><span class="small" title="${esc(a.Path)}">${esc(a.Path)}</span></td>
      <td class="num">${[...a.pids].join(', ')}</td><td class="num">${a.total}</td><td class="num">${a.ext}</td><td class="num">${a.extIn}</td><td class="num">${a.extOut}</td>
      <td><span class="small" title="${esc([...a.hosts].join('\n'))}">${esc([...a.hosts].slice(0,6).join(', '))}${a.hosts.size>6?' …':''}</span></td></tr>`); });
    out = table([['rr','Risk'],['App','App'],['pids','PID'],['total','Connections'],['ext','External'],['extIn','Ext. in'],['extOut','Ext. out'],['nhosts','Remote hosts']], rows, 'apps');
  } else {
    const q = S.q.trim().toLowerCase();
    const rows = sortRows(d.listeners.filter(l => (!S.risky || l.Risk) && (!q || [l.App, l.Description, l.Services, l.LocalPort, l.Protocol].join(' ').toLowerCase().includes(q)))
      .map(l => ({...l, rr: RANK[l.Risk] || 0})), 'listen').map(l =>
      `<tr${rowAttrs(l.Risk, l.Issues, l.App + ' (port ' + l.LocalPort + ')')}><td>${riskPill(l.Risk)}</td><td><span class="app" data-ai="${esc(l.App)}" data-svc="${esc(l.Services)}">${esc(appLabel(l))}</span><span class="small">${esc(l.Path)}</span></td><td class="num">${l.PID}</td><td>${l.Protocol}</td>
      <td class="num">${esc(l.LocalAddress)}</td><td class="num">${l.LocalPort}</td><td><span class="pill ${l.Exposed?'in':'lan'}">${l.Exposed?'Reachable from network':'This PC only'}</span></td></tr>`);
    out = table([['rr','Risk'],['App','App'],['PID','PID'],['Protocol','Proto'],['LocalAddress','Address'],['LocalPort','Port'],['Exposed','Exposure']], rows, 'listen');
  }
  $('#view').innerHTML = out;
}

// controls
$('#q').value = S.q; $('#dir').value = S.dir; $('#ext').checked = S.ext; $('#closed').checked = S.closed;
$('#q').oninput = e => { S.q = e.target.value; save(); render(); };
$('#dir').onchange = e => { S.dir = e.target.value; save(); render(); };
$('#ext').onchange = e => { S.ext = e.target.checked; save(); render(); };
$('#closed').onchange = e => { S.closed = e.target.checked; save(); render(); };
$('#risky').checked = S.risky;
$('#risky').onchange = e => { S.risky = e.target.checked; save(); render(); };

// hover tooltip: what's wrong and how to fix it
const tip = $('#tip');
document.addEventListener('mousemove', e => {
  if (!e.target.closest || e.target.closest('[data-ai], #ainfo')) { tip.style.display = 'none'; return; }
  const row = e.target.closest('tr[data-tip]');
  const t = row && TIPS[+row.dataset.tip];
  if (!t) { tip.style.display = 'none'; return; }
  tip.className = t.risk;
  tip.innerHTML = `<h4>${esc(t.who)}: ${t.risk === 'high' ? 'risky' : 'worth checking'}</h4>` +
    t.issues.map(i => `<p><span class="lvl ${i.Level}">${i.Level === 'high' ? 'Risk' : 'Check'}:</span> ${esc(i.Text)}</p>`).join('');
  tip.style.display = 'block';
  const w = tip.offsetWidth, h = tip.offsetHeight;
  tip.style.left = Math.min(e.clientX + 14, innerWidth - w - 8) + 'px';
  tip.style.top = (e.clientY + 16 + h > innerHeight ? e.clientY - h - 12 : e.clientY + 16) + 'px';
});
$('#tabs').onclick = e => { if (e.target.dataset.t) { S.tab = e.target.dataset.t; save(); render(); } };
$('#view').onclick = e => {
  const th = e.target.closest('th'); if (th) { const s = S.sort[th.dataset.key]; S.sort[th.dataset.key] = [th.dataset.k, s[0] === th.dataset.k ? -s[1] : 1]; save(); render(); return; }
  const a = e.target.closest('a[data-app]'); if (a) { S.q = a.dataset.app; S.tab = 'conn'; $('#q').value = S.q; save(); render(); }
};

// hover popup on app names: built-in or not, what it does, risks, links
const ainfo = $('#ainfo');
let aiTimer = null, aiOpen = false;
const GENERIC_RISK = {
  windows: 'Normal Windows component. Only suspicious if the file is outside C:\\Windows.',
  microsoft: 'Microsoft software installed on top of Windows. Normal if you use it; uninstall it from Settings > Apps > Installed apps if not.',
  thirdparty: 'Installed by you or your PC maker. Fine if you recognise it; if not, look it up below and uninstall it from Settings > Apps > Installed apps.',
  unsigned: 'No valid digital signature, so the publisher can\'t be verified. In File Explorer right-click the file > Scan with Microsoft Defender, and remove it if you don\'t recognise it.',
  unknown: 'Windows hid where this program lives. Restart NetMonitor as Administrator to identify it.'
};
function showAppInfo(el) {
  const d = window.NETDATA || {}, name = el.dataset.ai, info = (d.apps || {})[name] || {}, kb = kbFor(name);
  let origin = info.Origin || 'unknown', guessed = false;
  if (origin === 'unknown' && kb) { origin = {w:'windows', m:'microsoft', t:'thirdparty'}[kb[0]]; guessed = true; }
  const [olabel, ocls] = ORIGIN[origin] || ORIGIN.unknown;
  const what = kb ? kb[1] : [info.Description, info.Product && info.Product !== info.Description ? '(' + info.Product + ')' : ''].join(' ').trim() || 'No description available.';
  const svcs = (el.dataset.svc || '').split(', ').filter(Boolean);
  const svcHtml = !svcs.length ? '' : '<div class="sec"><b>Windows services running inside it</b><ul>' +
    svcs.slice(0, 6).map(s => { const x = (d.services || {})[s]; return `<li><strong>${esc(x ? x.d : s)}</strong>${x && x.s ? ': ' + esc(x.s) : ''}</li>`; }).join('') +
    (svcs.length > 6 ? `<li>…and ${svcs.length - 6} more</li>` : '') + '</ul></div>';
  const disguise = kb && kb[0] === 'w' && info.Path && !/^[a-z]:\\windows\\/i.test(info.Path)
    ? '<div class="sec" style="color:var(--risk)"><b style="color:var(--risk)">Warning</b>This name belongs to Windows, but this copy runs from outside C:\\Windows, which is a common malware disguise. Run a full Defender scan.</div>' : '';
  const signed = info.Publisher ? `Signed by <strong>${esc(info.Publisher)}</strong>` : info.Path ? 'No valid digital signature' : '';
  const company = info.Company && info.Company !== info.Publisher ? `${signed ? ' · ' : ''}Company: ${esc(info.Company)}` : '';
  const exe = name + '.exe';
  const links = [];
  if (kb && kb[3]) links.push(`<a href="${kb[3]}" target="_blank" rel="noopener">Official page</a>`);
  if (origin === 'windows' || origin === 'microsoft') links.push(`<a href="https://learn.microsoft.com/en-us/search/?terms=${encodeURIComponent(exe)}" target="_blank" rel="noopener">Microsoft docs</a>`);
  links.push(`<a href="https://www.bing.com/search?q=${encodeURIComponent((exe + ' ' + (info.Company || '') + ' what is it safe').replace(/\s+/g, ' '))}" target="_blank" rel="noopener">Search the web</a>`);
  ainfo.innerHTML = `<h4>${esc(exe)}</h4><span class="origin ${ocls}">${esc(olabel)}</span>` +
    (guessed ? ' <span class="small" style="display:inline">based on its name; run as Administrator to verify the file</span>' : '') + disguise +
    `<div class="sec"><b>What it does</b>${esc(what)}</div>` + svcHtml +
    `<div class="sec"><b>Risks</b>${esc(kb ? kb[2] : GENERIC_RISK[origin])}</div>` +
    `<div class="sec"><b>Where it lives</b>${info.Path ? `<div class="path">${esc(info.Path)}</div>` : '<span class="small" style="display:inline">Hidden: run as Administrator to see it</span>'}` +
    (signed || company ? `<div>${signed}${company}</div>` : '') + '</div>' +
    `<div class="sec links"><b>Find it online</b>${links.join('')}</div>`;
  ainfo.style.display = 'block'; aiOpen = true;
  const r = el.getBoundingClientRect(), w = ainfo.offsetWidth, h = ainfo.offsetHeight;
  ainfo.style.left = Math.max(8, Math.min(r.left, innerWidth - w - 8)) + 'px';
  ainfo.style.top = (r.bottom + 6 + h > innerHeight && r.top - h - 6 > 0 ? r.top - h - 6 : r.bottom + 6) + 'px';
}
function hideAppInfo() { ainfo.style.display = 'none'; aiOpen = false; }
document.addEventListener('mouseover', e => {
  const el = e.target.closest && e.target.closest('[data-ai]');
  clearTimeout(aiTimer);
  if (el) aiTimer = setTimeout(() => showAppInfo(el), 250);
  else if (e.target.closest && e.target.closest('#ainfo')) return;      // keep open while reading / clicking links
  else if (aiOpen) aiTimer = setTimeout(hideAppInfo, 300);
});

// live reload of data.js (works from file:// without a server)
let interval = 3000;
function poll() {
  const s = document.createElement('script');
  s.src = 'data.js?t=' + Date.now();
  s.onload = () => { s.remove(); if (window.NETDATA) interval = window.NETDATA.interval * 1000; render(); setTimeout(poll, interval); };
  s.onerror = () => { s.remove(); setTimeout(poll, interval); };
  document.head.appendChild(s);
}
poll();
</script>
</body>
</html>
'@
[IO.File]::WriteAllText($htmlPath, $html, $utf8)

# ---------------------------------------------------------------- main loop

$conns      = @{}
$dnsNames   = @{}
$rdnsTasks  = @{}
$rdnsTried  = New-Object 'System.Collections.Generic.HashSet[string]'
$prevBytes  = $null
$prevTime   = $null
$browserOpened = $false
$skipStates = @('Listen', 'Bound', 'TimeWait', 'Closed', 'DeleteTCB')

Write-Host "NetMonitor running. Dashboard: $htmlPath"
Write-Host "CSV log:   $csvPath"
if (-not $isAdmin) { Write-Host 'Tip: run as Administrator to resolve paths for all processes.' -ForegroundColor Yellow }
Write-Host 'Press Ctrl+C to stop.'

while ($true) {
  $now = Get-Date

  # drop cached info for processes that exited (PIDs get reused)
  $livePids = New-Object 'System.Collections.Generic.HashSet[int]'
  Get-Process | ForEach-Object { [void]$livePids.Add($_.Id) }
  foreach ($k in @($procCache.Keys)) { if (-not $livePids.Contains($k)) { $procCache.Remove($k) } }
  if (($now - $svcRefreshed).TotalSeconds -ge 30) { Update-ServiceMap }

  # hostnames: Windows DNS cache first (what the app actually looked up), reverse DNS as fallback
  try {
    Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } |
      ForEach-Object { if ($_.Data) { $dnsNames[[string]$_.Data] = $_.Entry } }
  } catch {}
  foreach ($ip in @($rdnsTasks.Keys)) {
    $t = $rdnsTasks[$ip]
    if ($t.IsCompleted) {
      if ($t.Status -eq 'RanToCompletion' -and -not $dnsNames.ContainsKey($ip)) { $dnsNames[$ip] = $t.Result.HostName }
      $rdnsTasks.Remove($ip)
    }
  }

  $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
  $listenPorts = New-Object 'System.Collections.Generic.HashSet[int]'
  $tcp | Where-Object State -eq 'Listen' | ForEach-Object { [void]$listenPorts.Add([int]$_.LocalPort) }

  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  $newRows = New-Object System.Collections.ArrayList

  foreach ($c in $tcp) {
    $state = [string]$c.State
    if ($skipStates -contains $state) { continue }
    $remote = [string]$c.RemoteAddress
    if ($remote -eq '0.0.0.0' -or $remote -eq '::') { continue }

    $procId = [int]$c.OwningProcess
    $key = "TCP|$($c.LocalAddress)|$($c.LocalPort)|$remote|$($c.RemotePort)|$procId"
    [void]$seen.Add($key)

    $external = Test-ExternalIP $remote
    $remoteHost = ''
    if ($dnsNames.ContainsKey($remote)) { $remoteHost = $dnsNames[$remote] }
    elseif ($external -and $rdnsTried.Add($remote)) {
      try { $rdnsTasks[$remote] = [System.Net.Dns]::GetHostEntryAsync($remote) } catch {}
    }

    if ($conns.ContainsKey($key)) {
      $r = $conns[$key]
      $r.State = $state; $r.LastSeen = $now.ToString('o'); $r.Closed = $null
      if ($remoteHost) { $r.RemoteHost = $remoteHost }
      continue
    }

    $pi = Get-ProcInfo $procId
    $svc = ''; if ($svcMap.ContainsKey($procId)) { $svc = $svcMap[$procId] }
    $direction = $(if ($listenPorts.Contains([int]$c.LocalPort)) { 'Inbound' } else { 'Outbound' })
    $issues = @(Get-AppIssues $pi)
    if ($external -and $direction -eq 'Inbound') {
      $issues += New-Issue 'high' "A computer on the internet ($remote) is connected INTO '$($pi.Name)'. Unexpected unless you run a server or game host. Fix: end the app in Task Manager, then Windows Security > Firewall & network protection > Allow an app through firewall > untick it. Also check your router's port-forwarding settings."
    }
    $rp = [int]$c.RemotePort
    if ($external -and $badPorts.ContainsKey($rp)) {
      $issues += New-Issue 'high' "Talking to the internet on port $rp, which is $($badPorts[$rp]). Fix: unless you recognise this, end '$($pi.Name)' in Task Manager and run a full Defender scan (Windows Security > Virus & threat protection > Scan options > Full scan)."
    }
    if ($external -and ($rp -eq 23 -or $rp -eq 21)) {
      $issues += New-Issue 'medium' "Uses an unencrypted login protocol (port $rp), so passwords can be read in transit. Fix: use an SFTP or SSH client instead."
    }
    $r = [pscustomobject]@{
      Risk          = Get-RiskLevel $issues
      Issues        = @($issues)
      Publisher     = $pi.Publisher
      Direction     = $direction
      External      = $external
      App           = $pi.Name
      Description   = $pi.Description
      Services      = $svc
      Path          = $pi.Path
      PID           = $procId
      Protocol      = 'TCP'
      LocalAddress  = [string]$c.LocalAddress
      LocalPort     = [int]$c.LocalPort
      RemoteAddress = $remote
      RemotePort    = [int]$c.RemotePort
      RemoteHost    = $remoteHost
      State         = $state
      FirstSeen     = $now.ToString('o')
      LastSeen      = $now.ToString('o')
      Closed        = $null
    }
    $conns[$key] = $r
    [void]$newRows.Add($r)
  }

  # mark vanished connections closed, prune old ones
  foreach ($k in @($conns.Keys)) {
    $r = $conns[$k]
    if (-not $seen.Contains($k)) {
      if (-not $r.Closed) { $r.Closed = $now.ToString('o') }
      elseif (($now - [datetime]$r.Closed).TotalMinutes -ge $ClosedRetentionMinutes) { $conns.Remove($k) }
    }
  }

  # log new connections. Text that starts with = + - @ is prefixed with ' so Excel won't run it as a
  # formula: remote hostnames come from reverse DNS, which the remote server's owner controls.
  if ($newRows.Count) {
    $newRows | Select-Object @{n='Time';e={$_.FirstSeen}}, Risk, Direction, External, App, PID, Services, Path, Protocol,
      LocalAddress, LocalPort, RemoteAddress, RemotePort, RemoteHost, @{n='Issues';e={($_.Issues | ForEach-Object Text) -join ' | '}} |
      ForEach-Object {
        foreach ($prop in $_.PSObject.Properties) {
          if ($prop.Value -is [string] -and $prop.Value -match '^[=+\-@\t\r]') { $prop.Value = "'" + $prop.Value }
        }
        $_
      } |
      Export-Csv -Path $csvPath -Append -NoTypeInformation -Encoding UTF8 -Force
  }

  # listening sockets (what can receive inbound traffic)
  $listeners = New-Object System.Collections.ArrayList
  $lseen = New-Object 'System.Collections.Generic.HashSet[string]'
  $sockets = @()
  $sockets += $tcp | Where-Object State -eq 'Listen' | ForEach-Object { [pscustomobject]@{P='TCP'; A=[string]$_.LocalAddress; Port=[int]$_.LocalPort; Id=[int]$_.OwningProcess} }
  $sockets += @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue) | ForEach-Object { [pscustomobject]@{P='UDP'; A=[string]$_.LocalAddress; Port=[int]$_.LocalPort; Id=[int]$_.OwningProcess} }
  foreach ($s in $sockets) {
    if (-not $lseen.Add("$($s.P)|$($s.A)|$($s.Port)|$($s.Id)")) { continue }
    $pi = Get-ProcInfo $s.Id
    $svc = ''; if ($svcMap.ContainsKey($s.Id)) { $svc = $svcMap[$s.Id] }
    $loop = $s.A -like '127.*' -or $s.A -eq '::1'
    $issues = @()
    if (-not $loop) {
      $issues += @(Get-AppIssues $pi)
      if ($s.P -eq 'TCP' -and $exposedPortRisk.ContainsKey($s.Port)) {
        $issues += New-Issue $exposedPortRisk[$s.Port][0] $exposedPortRisk[$s.Port][1]
      }
      if ($onPublicNetwork -and $s.P -eq 'TCP' -and ($s.Port -eq 445 -or $s.Port -eq 139)) {
        $issues += New-Issue 'medium' 'File sharing is open while you''re on a Public network (cafe, hotel). Fix: Settings > Network & internet > Advanced network settings > Advanced sharing settings > turn off File and printer sharing for Public networks.'
      }
    }
    [void]$listeners.Add([pscustomobject]@{
      Risk = Get-RiskLevel $issues; Issues = @($issues); Publisher = $pi.Publisher
      App = $pi.Name; Description = $pi.Description; Services = $svc; Path = $pi.Path; PID = $s.Id
      Protocol = $s.P; LocalAddress = $s.A; LocalPort = $s.Port; Exposed = -not $loop
    })
  }

  # overall throughput from physical adapters
  $rxRate = $null; $txRate = $null
  $bytes = Get-AdapterBytes
  if ($bytes -and $prevBytes) {
    $secs = ($now - $prevTime).TotalSeconds
    if ($secs -gt 0) { $rxRate = [math]::Max(0, ($bytes.Rx - $prevBytes.Rx) / $secs); $txRate = [math]::Max(0, ($bytes.Tx - $prevBytes.Tx) / $secs) }
  }
  $prevBytes = $bytes; $prevTime = $now

  # per-app details for the app-name tooltip (keyed by process name)
  $appInfo = @{}
  foreach ($pi in $procCache.Values) {
    if ($appInfo.ContainsKey($pi.Name) -and $appInfo[$pi.Name].Path) { continue }
    $appInfo[$pi.Name] = [pscustomobject]@{ Origin = $pi.Origin; Path = $pi.Path; Publisher = $pi.Publisher; Signature = $pi.Signature
                                            Company = $pi.Company; Product = $pi.Product; Description = $pi.Description }
  }

  $payload = [ordered]@{
    generated   = $now.ToString('o')
    host        = $env:COMPUTERNAME
    admin       = $isAdmin
    interval    = $IntervalSeconds
    rxRate      = $rxRate
    txRate      = $txRate
    connections = @($conns.Values)
    listeners   = @($listeners)
    apps        = $appInfo
    services    = $svcInfo
  }
  $json = ConvertTo-Json -InputObject $payload -Depth 5 -Compress
  try { [IO.File]::WriteAllText($dataPath, "window.NETDATA=$json;", $utf8) } catch {}  # browser may hold the file briefly

  if (-not $browserOpened -and -not $NoBrowser) { Start-Process $htmlPath; $browserOpened = $true }
  if ($Once) { break }
  Start-Sleep -Seconds $IntervalSeconds
}
