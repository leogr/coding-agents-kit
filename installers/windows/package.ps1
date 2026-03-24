#Requires -Version 5.1
<#
.SYNOPSIS
    Build the coding-agents-kit Windows MSI package.

.DESCRIPTION
    Compiles Rust crates, builds Falco from source (if needed), stages
    all files, and produces an MSI installer via WiX v4.

.PARAMETER Version
    Package version (default: 0.1.0).

.PARAMETER Arch
    Target architecture: x64 or arm64 (default: native).

.PARAMETER SkipFalcoBuild
    Skip building Falco (use pre-built binary).

.PARAMETER SkipRustBuild
    Skip building Rust crates (use pre-built binaries).

.PARAMETER FalcoExe
    Path to pre-built falco.exe (overrides Falco build).
#>
param(
    [string]$Version = '0.1.0',
    [string]$Arch = '',
    [switch]$SkipFalcoBuild,
    [switch]$SkipRustBuild,
    [string]$FalcoExe = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$BuildDir = Join-Path $RootDir 'build'

# Detect native architecture
if ([string]::IsNullOrWhiteSpace($Arch)) {
    $nativeArch = $env:PROCESSOR_ARCHITECTURE
    switch ($nativeArch) {
        'AMD64' { $Arch = 'x64' }
        'ARM64' { $Arch = 'arm64' }
        default { $Arch = 'x64' }
    }
}

# Map to Rust target
$RustTarget = switch ($Arch) {
    'x64'   { 'x86_64-pc-windows-msvc' }
    'arm64' { 'aarch64-pc-windows-msvc' }
    default { throw "Unsupported architecture: $Arch" }
}

$WixArch = switch ($Arch) {
    'x64'   { 'x64' }
    'arm64' { 'arm64' }
    default { 'x64' }
}

Write-Host "coding-agents-kit Windows Package Builder"
Write-Host "  Version:  $Version"
Write-Host "  Arch:     $Arch"
Write-Host "  Target:   $RustTarget"
Write-Host ""

# ---------------------------------------------------------------------------
# Stage directory
# ---------------------------------------------------------------------------

$StageDir = Join-Path $BuildDir "stage-windows-$Arch"
if (Test-Path $StageDir) { Remove-Item $StageDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'bin') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'share') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'config') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'rules\default') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'rules\user') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'scripts') | Out-Null

# ---------------------------------------------------------------------------
# Build Rust crates
# ---------------------------------------------------------------------------

if (-not $SkipRustBuild) {
    Write-Host "=== Building Rust crates ($RustTarget) ==="

    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) { throw 'cargo not found. Install Rust toolchain.' }

    # Ensure target is installed
    & rustup target add $RustTarget 2>&1 | Out-Null

    Push-Location (Join-Path $RootDir 'hooks\claude-code')
    & cargo build --release --target $RustTarget
    if ($LASTEXITCODE -ne 0) { throw 'Interceptor build failed.' }
    Pop-Location

    Push-Location (Join-Path $RootDir 'plugins\coding-agent-plugin')
    & cargo build --release --target $RustTarget
    if ($LASTEXITCODE -ne 0) { throw 'Plugin build failed.' }
    Pop-Location

    Push-Location (Join-Path $RootDir 'tools\coding-agents-kit-ctl')
    & cargo build --release --target $RustTarget
    if ($LASTEXITCODE -ne 0) { throw 'CTL tool build failed.' }
    Pop-Location
}

# ---------------------------------------------------------------------------
# Build Falco
# ---------------------------------------------------------------------------

$FalcoDir = Join-Path $BuildDir "falco-0.43.0-windows-$Arch"

if ([string]::IsNullOrWhiteSpace($FalcoExe)) {
    if (-not $SkipFalcoBuild) {
        if (-not (Test-Path (Join-Path $FalcoDir 'falco.exe'))) {
            Write-Host "=== Building Falco ==="
            & (Join-Path $ScriptDir 'build-falco.ps1') -Arch $Arch
            if ($LASTEXITCODE -ne 0) { throw 'Falco build failed.' }
        }
    }
    $FalcoExe = Join-Path $FalcoDir 'falco.exe'
}

if (-not (Test-Path $FalcoExe)) { throw "Falco binary not found: $FalcoExe" }

# ---------------------------------------------------------------------------
# Patch falco.exe plugin search path
# ---------------------------------------------------------------------------

Write-Host "Patching falco.exe plugin search path..."
$falcoBytes = [System.IO.File]::ReadAllBytes($FalcoExe)
$searchBytes = [System.Text.Encoding]::ASCII.GetBytes('/usr/share/falco/plugins/')
$replaceBytes = New-Object byte[] $searchBytes.Length
$replaceBytes[0] = [byte][char]'.'
$replaceBytes[1] = [byte][char]'/'

$patched = $false
for ($i = 0; $i -le $falcoBytes.Length - $searchBytes.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $searchBytes.Length; $j++) {
        if ($falcoBytes[$i + $j] -ne $searchBytes[$j]) { $match = $false; break }
    }
    if ($match) {
        for ($j = 0; $j -lt $replaceBytes.Length; $j++) { $falcoBytes[$i + $j] = $replaceBytes[$j] }
        $patched = $true
        Write-Host "  Patched at offset $i"
        break
    }
}

$stagedFalco = Join-Path $StageDir 'bin\falco.exe'
[System.IO.File]::WriteAllBytes($stagedFalco, $falcoBytes)
if (-not $patched) { Write-Host "  WARNING: plugin path pattern not found (may already be patched)" }

# ---------------------------------------------------------------------------
# Stage binaries
# ---------------------------------------------------------------------------

Write-Host "Staging files..."

# Find built artifacts: check target-specific dir first, then default release/
function Find-Artifact([string]$CrateDir, [string]$FileName) {
    $candidates = @(
        (Join-Path $CrateDir "target\$RustTarget\release\$FileName"),
        (Join-Path $CrateDir "target\release\$FileName")
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    throw "Built artifact not found: $FileName (looked in $($candidates -join ', '))"
}

Copy-Item (Find-Artifact (Join-Path $RootDir 'hooks\claude-code') 'claude-interceptor.exe') (Join-Path $StageDir 'bin\') -Force
Copy-Item (Find-Artifact (Join-Path $RootDir 'tools\coding-agents-kit-ctl') 'coding-agents-kit-ctl.exe') (Join-Path $StageDir 'bin\') -Force
Copy-Item (Find-Artifact (Join-Path $RootDir 'plugins\coding-agent-plugin') 'coding_agent_plugin.dll') (Join-Path $StageDir 'share\') -Force

Copy-Item (Join-Path $ScriptDir 'coding-agents-kit-launcher.ps1') (Join-Path $StageDir 'bin\') -Force

# ---------------------------------------------------------------------------
# Stage rules
# ---------------------------------------------------------------------------

Copy-Item (Join-Path $RootDir 'rules\default\coding_agents_rules.yaml') (Join-Path $StageDir 'rules\default\') -Force
Copy-Item (Join-Path $RootDir 'rules\seen.yaml') (Join-Path $StageDir 'rules\') -Force

# ---------------------------------------------------------------------------
# Stage scripts
# ---------------------------------------------------------------------------

Copy-Item (Join-Path $ScriptDir 'scripts\postinstall.ps1') (Join-Path $StageDir 'scripts\') -Force
Copy-Item (Join-Path $ScriptDir 'scripts\uninstall.ps1') (Join-Path $StageDir 'scripts\') -Force

Write-Host "  Staged to: $StageDir"

# ---------------------------------------------------------------------------
# Deterministic ProductCode from version
# ---------------------------------------------------------------------------

$versionBytes = [System.Text.Encoding]::UTF8.GetBytes("coding-agents-kit-ProductCode-$Version")
$sha = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha.ComputeHash($versionBytes)
$guidBytes = $hashBytes[0..15]
$guidBytes[6] = ($guidBytes[6] -band 0x0F) -bor 0x50   # UUID version 5
$guidBytes[8] = ($guidBytes[8] -band 0x3F) -bor 0x80   # RFC 4122 variant
$ProductCode = [System.Guid]::new([byte[]]$guidBytes).ToString('B').ToUpper()
Write-Host "  ProductCode: $ProductCode"

# ---------------------------------------------------------------------------
# Build MSI
# ---------------------------------------------------------------------------

$WxsFile = Join-Path $ScriptDir 'Package.wxs'
$OutputDir = Join-Path $BuildDir 'out'
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$MsiName = "coding-agents-kit-$Version-windows-$Arch.msi"

Write-Host "Building MSI..."

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) { throw 'WiX Toolset not found. Install via: dotnet tool install --global wix' }

& wix build $WxsFile `
    -d "StageDir=$StageDir" `
    -d "ProductVersion=$Version" `
    -d "ProductCode=$ProductCode" `
    -o (Join-Path $OutputDir $MsiName) `
    -arch $WixArch

if ($LASTEXITCODE -ne 0) { throw 'WiX build failed.' }

# ---------------------------------------------------------------------------
# Emit companion uninstall script
# ---------------------------------------------------------------------------

$uninstallScript = Join-Path $OutputDir 'Uninstall-CodingAgentsKit.ps1'
@"
# Uninstall coding-agents-kit $Version
`$p = Start-Process msiexec -ArgumentList '/x', '$ProductCode', '/quiet' -Wait -PassThru
if (`$p.ExitCode -ne 0) { Write-Error "Uninstall failed (exit `$(`$p.ExitCode))" }
"@ | Set-Content $uninstallScript -Encoding UTF8

Write-Host ""
Write-Host "MSI created: $(Join-Path $OutputDir $MsiName)"
Write-Host ""
Write-Host "Install:   msiexec /i $MsiName"
Write-Host "Silent:    msiexec /i $MsiName /quiet"
Write-Host "Uninstall: powershell -File Uninstall-CodingAgentsKit.ps1"
