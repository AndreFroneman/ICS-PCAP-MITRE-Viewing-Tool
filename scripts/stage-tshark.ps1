# Stages Wireshark 4.6.9's tshark into src-tauri/resources/engines.
# The silent installer does not install Npcap. This script also refuses to copy an Npcap installer.
# Source that matches this binary: https://www.wireshark.org/download/src/all-versions/wireshark-4.6.9.tar.xz
$ErrorActionPreference = "Stop"
$Version = "4.6.9"
$Url = "https://www.wireshark.org/download/win64/Wireshark-$Version-x64.exe"
$Sha256 = "bf9b5ce8a89f244c376a9b1a946276eaa06463dde3e33069a34d7f102f5878cf"
$SourceUrl = "https://www.wireshark.org/download/src/all-versions/wireshark-$Version.tar.xz"
$SourceSha = "d062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f"
$Work = Join-Path $env:TEMP "primer-wireshark"
$Install = "C:\WiresharkStage"
$Dest = Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\src-tauri\resources\engines")).Path ""
New-Item -ItemType Directory -Force -Path $Work, $Dest | Out-Null
$Installer = Join-Path $Work "Wireshark-$Version-x64.exe"
Write-Host "Downloading $Url"
Invoke-WebRequest -Uri $Url -OutFile $Installer
$Hash = (Get-FileHash $Installer -Algorithm SHA256).Hash.ToLower()
if ($Hash -ne $Sha256) { throw "Wireshark installer hash mismatch: $Hash" }
if (Test-Path $Install) { Remove-Item -Recurse -Force $Install }
Write-Host "Silent install (Npcap is not installed by /S)"
$proc = Start-Process -FilePath $Installer -ArgumentList "/S", "/D=$Install" -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "Wireshark installer exited $($proc.ExitCode)" }
if (-not (Test-Path (Join-Path $Install "tshark.exe"))) { throw "tshark.exe was not produced" }
Get-ChildItem $Dest -Force | Remove-Item -Recurse -Force
Copy-Item (Join-Path $Install "tshark.exe") $Dest
Copy-Item (Join-Path $Install "dumpcap.exe") $Dest
Copy-Item (Join-Path $Install "*.dll") $Dest
foreach ($folder in @("plugins", "profiles", "extcap", "snmp", "radius", "diameter", "tpncp")) {
  $from = Join-Path $Install $folder
  if (Test-Path $from) { Copy-Item $from (Join-Path $Dest $folder) -Recurse }
}
Get-ChildItem $Dest -Recurse -Include "*npcap*","*Npcap*","*NPF*" -ErrorAction SilentlyContinue | Remove-Item -Force
$Source = Join-Path $Work "wireshark-$Version.tar.xz"
Invoke-WebRequest -Uri $SourceUrl -OutFile $Source
$SourceHash = (Get-FileHash $Source -Algorithm SHA256).Hash.ToLower()
if ($SourceHash -ne $SourceSha) { throw "Wireshark source hash mismatch: $SourceHash" }
$SourceOut = Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "src-tauri\target"
New-Item -ItemType Directory -Force -Path $SourceOut | Out-Null
Copy-Item $Source (Join-Path $SourceOut "wireshark-$Version.tar.xz")
Write-Host "Staged tshark from Wireshark $Version. Npcap was not copied."
Write-Host "SOURCE $(Join-Path $SourceOut "wireshark-$Version.tar.xz")"
