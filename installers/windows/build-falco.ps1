#Requires -Version 5.1
<#
.SYNOPSIS
    Build Falco from source on Windows with http_output support.

.DESCRIPTION
    Clones the Falco repository at a specific tag, applies patches to
    enable http_output on Windows, and builds with MSVC.
    Requires vcpkg with curl installed (SChannel backend, static).

.PARAMETER Version
    Falco version tag to build (default: 0.43.0).

.PARAMETER OutputDir
    Directory for the built falco.exe (default: build/falco-VERSION-windows-ARCH).

.PARAMETER Arch
    MSVC architecture target: x64 or arm64 (default: x64).

.PARAMETER Force
    Rebuild even if cached build exists.
#>
param(
    [string]$Version = '0.43.0',
    [string]$OutputDir = '',
    [string]$Arch = 'x64',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$BuildBase = Join-Path $RootDir 'build'
$SrcDir = Join-Path $BuildBase "falco-src-$Version"
$Tag = $Version

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $BuildBase "falco-$Version-windows-$Arch"
}

$FalcoExe = Join-Path $OutputDir 'falco.exe'
if ((Test-Path $FalcoExe) -and -not $Force) {
    Write-Host "Falco already built at $FalcoExe (use -Force to rebuild)"
    exit 0
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

function Resolve-RequiredCommand([string]$Name) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { throw "Missing required command: $Name" }
    return $cmd.Source
}

$Git = Resolve-RequiredCommand 'git'
$CMake = Resolve-RequiredCommand 'cmake'
$Tar = Resolve-RequiredCommand 'tar.exe'

# vcpkg is required for system curl (http_output uses curl to POST alerts).
$VcpkgRoot = $env:VCPKG_ROOT
if (-not $VcpkgRoot) { $VcpkgRoot = $env:VCPKG_INSTALLATION_ROOT }
if (-not $VcpkgRoot -or -not (Test-Path $VcpkgRoot)) {
    throw @"
vcpkg not found. Set VCPKG_ROOT to your vcpkg installation directory.
Install vcpkg:  git clone https://github.com/microsoft/vcpkg && .\vcpkg\bootstrap-vcpkg.bat
Install curl:   vcpkg install curl[schannel]:$Arch-windows-static
"@
}
$VcpkgToolchain = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
if (-not (Test-Path $VcpkgToolchain)) {
    throw "vcpkg toolchain file not found: $VcpkgToolchain"
}
$VcpkgTriplet = "$Arch-windows-static"

# Verify curl is installed in vcpkg for the target triplet.
$curlLib = Join-Path $VcpkgRoot "installed\$VcpkgTriplet\lib\libcurl.lib"
if (-not (Test-Path $curlLib)) {
    throw @"
curl not found in vcpkg for triplet $VcpkgTriplet.
Install:  vcpkg install curl[schannel]:$VcpkgTriplet
"@
}

# Find vcvarsall.bat
$VcVarsAll = $null
$vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path $vsWhere) {
    $installPath = & $vsWhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null
    if ($installPath) {
        $candidate = Join-Path $installPath 'VC\Auxiliary\Build\vcvarsall.bat'
        if (Test-Path $candidate) { $VcVarsAll = $candidate }
    }
}
if (-not $VcVarsAll) {
    $candidates = Get-ChildItem 'C:\Program Files\Microsoft Visual Studio' -Recurse `
        -Filter vcvarsall.bat -ErrorAction SilentlyContinue
    if ($candidates) { $VcVarsAll = $candidates[0].FullName }
}
if (-not $VcVarsAll) { throw 'Could not find vcvarsall.bat. Install Visual Studio Build Tools.' }

# ---------------------------------------------------------------------------
# Clone Falco source
# ---------------------------------------------------------------------------

if (-not (Test-Path (Join-Path $SrcDir 'CMakeLists.txt'))) {
    Write-Host "=== Cloning Falco $Tag ==="
    if (Test-Path $SrcDir) { Remove-Item $SrcDir -Recurse -Force }
    # Git writes progress to stderr; temporarily allow non-terminating errors
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $Git clone --depth 1 --branch $Tag `
        https://github.com/falcosecurity/falco.git $SrcDir 2>&1 | ForEach-Object { Write-Host $_ }
    $ErrorActionPreference = $prevPref
    if ($LASTEXITCODE -ne 0) { throw 'Failed to clone Falco.' }
    if (-not (Test-Path (Join-Path $SrcDir 'CMakeLists.txt'))) {
        throw 'Falco clone completed but CMakeLists.txt not found.'
    }
}

# ---------------------------------------------------------------------------
# Apply patches
# ---------------------------------------------------------------------------

$PatchDir = $ScriptDir  # patches are alongside this script
$patches = @(
    (Join-Path $PatchDir 'falco-windows-http-output.patch'),
    (Join-Path $PatchDir 'falco-windows-curl-noproxy.patch')
)

foreach ($patchPath in $patches) {
    if (-not (Test-Path $patchPath)) {
        Write-Host "Patch not found, skipping: $patchPath"
        continue
    }
    $patchName = Split-Path $patchPath -Leaf
    # Check if already applied (git apply --check writes to stderr, suppress errors)
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $null = & $Git -c safe.directory=* -C $SrcDir apply --check --whitespace=nowarn `
        --recount --ignore-whitespace $patchPath 2>&1
    $checkExit = $LASTEXITCODE
    $ErrorActionPreference = $prevPref
    if ($checkExit -ne 0) {
        Write-Host "Patch already applied or does not apply cleanly, skipping: $patchName"
        continue
    }

    Write-Host "Applying patch: $patchName"

    # Normalise patch for git apply on Windows (CRLF handling)
    $tmpPatch = Join-Path $env:TEMP "falco-apply-$patchName"
    $lines = [System.IO.File]::ReadAllLines($patchPath)
    $inHunk = $false
    $normalised = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        $line = $line.TrimEnd("`r")
        if ($line -match '^@@') { $inHunk = $true }
        if ($inHunk -and $line -eq '') { $line = ' ' }
        $normalised.Add($line)
    }
    while ($normalised.Count -gt 0 -and $normalised[$normalised.Count - 1].Trim() -eq '') {
        $normalised.RemoveAt($normalised.Count - 1)
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllLines($tmpPatch, $normalised, $utf8NoBom)

    & $Git -c safe.directory=* -C $SrcDir apply --whitespace=nowarn --recount --ignore-whitespace $tmpPatch
    if ($LASTEXITCODE -ne 0) { throw "Patch apply failed: $patchName" }
    Remove-Item $tmpPatch -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

$BuildDir = Join-Path $BuildBase "falco-build-$Version-$Arch"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "=== Building Falco $Version ($Arch) ==="

$cmdPath = Join-Path $BuildDir 'build-falco.cmd'
$script = @"
@echo off
setlocal
call "$VcVarsAll" $Arch
if %ERRORLEVEL% neq 0 exit /b 1

"$CMake" -S "$SrcDir" -B "$BuildDir" -G "NMake Makefiles" ^
    -DUSE_BUNDLED_DEPS=ON ^
    -DUSE_BUNDLED_CURL=OFF ^
    -DCMAKE_TOOLCHAIN_FILE="$VcpkgToolchain" ^
    -DVCPKG_TARGET_TRIPLET=$VcpkgTriplet ^
    -DMINIMAL_BUILD=ON ^
    -DBUILD_FALCO_MODERN_BPF=OFF ^
    -DBUILD_WARNINGS_AS_ERRORS=OFF ^
    -DBUILD_FALCO_UNIT_TESTS=OFF ^
    -DCREATE_TEST_TARGETS=OFF ^
    -DCMAKE_BUILD_TYPE=Release
if %ERRORLEVEL% neq 0 exit /b 1

"$CMake" --build "$BuildDir" --target falco
if %ERRORLEVEL% neq 0 exit /b 1
exit /b 0
"@
Set-Content -Path $cmdPath -Value $script -Encoding ASCII

try {
    & cmd.exe /d /c $cmdPath
    if ($LASTEXITCODE -ne 0) { throw 'Falco Windows build failed.' }
} finally {
    Remove-Item $cmdPath -Force -ErrorAction SilentlyContinue
}

# Find the built falco.exe
$builtExe = $null
foreach ($candidate in @(
    (Join-Path $BuildDir 'userspace\falco\falco.exe'),
    (Join-Path $BuildDir 'userspace\falco\Release\falco.exe')
)) {
    if (Test-Path $candidate) { $builtExe = $candidate; break }
}
if (-not $builtExe) { throw 'falco.exe not found after build.' }

Copy-Item $builtExe $FalcoExe -Force
Write-Host "Falco built: $FalcoExe"
