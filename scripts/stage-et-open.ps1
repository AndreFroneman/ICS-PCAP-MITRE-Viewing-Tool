# Copies a local Emerging Threats Open tarball into the resources tree.
# Fails if the archive or its LICENSE is missing. Does not download anything.
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Archive = Join-Path $Root "third-party\emerging-threats-open.tar.gz"
if (-not (Test-Path $Archive)) {
  throw "ET Open snapshot not found at third-party\emerging-threats-open.tar.gz. Primer does not download rules."
}
$Dest = Join-Path $Root "src-tauri\resources\rules\et-open"
if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
tar -xzf $Archive -C $Dest
$License = Get-ChildItem $Dest -Recurse -Filter "LICENSE" | Select-Object -First 1
if (-not $License) { throw "The ET Open snapshot has no LICENSE file. Refusing to stage it." }
Write-Host "Staged ET Open from $($License.FullName)"
