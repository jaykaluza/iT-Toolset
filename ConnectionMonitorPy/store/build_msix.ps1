# Builds store\out\MyConnections.msix from dist\MyConnections.exe.
# Usage: .\build_msix.ps1 -Name "<Package/Identity/Name>" -Publisher "CN=<Package/Identity/Publisher>"
# Both values come from Partner Center (Product management > Product identity). They are never guessed.
param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Publisher)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot; $root = Split-Path $here
$exe = Join-Path $root 'dist\MyConnections.exe'
$ver = (Get-Item $exe).VersionInfo.FileVersion        # e.g. 1.18.0.0
$stage = Join-Path $here 'out\stage'; $out = Join-Path $here 'out\MyConnections.msix'
Remove-Item (Join-Path $here 'out') -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$stage\Assets" -Force | Out-Null
Copy-Item $exe $stage
Add-Type -AssemblyName System.Drawing
$logo = [Drawing.Image]::FromFile((Resolve-Path (Join-Path $root '..\docs\logo.png')))   # 1280x440, white on black
function New-Icon($file, $w, $h) {   # logo scaled to fit, centred on black
  $bmp = New-Object Drawing.Bitmap $w, $h; $g = [Drawing.Graphics]::FromImage($bmp)
  $g.Clear([Drawing.Color]::Black); $g.InterpolationMode = 'HighQualityBicubic'
  $s = [Math]::Min(($w * 0.92) / $logo.Width, ($h * 0.92) / $logo.Height)
  $lw = $logo.Width * $s; $lh = $logo.Height * $s
  $g.DrawImage($logo, ($w - $lw) / 2, ($h - $lh) / 2, $lw, $lh)
  $bmp.Save("$stage\Assets\$file", [Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()
}
New-Icon 'StoreLogo.png' 50 50; New-Icon 'Square44x44Logo.png' 44 44
New-Icon 'Square150x150Logo.png' 150 150; New-Icon 'Wide310x150Logo.png' 310 150
(Get-Content (Join-Path $here 'AppxManifest.template.xml') -Raw).Replace('@@NAME@@', $Name).Replace('@@PUBLISHER@@', $Publisher).Replace('@@VERSION@@', $ver) |
  Set-Content "$stage\AppxManifest.xml" -Encoding UTF8
$mk = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe' | Sort-Object FullName | Select-Object -Last 1
& $mk.FullName pack /d $stage /p $out /o
Write-Host "Built $out (unsigned: the Store signs it for you)"
