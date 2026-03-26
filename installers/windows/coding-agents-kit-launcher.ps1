#Requires -Version 5.1
<#
.SYNOPSIS
    Launches the coding-agents-kit Falco service on Windows.

.DESCRIPTION
    Registers the Claude Code hook, starts Falco piped through the
    stdout-forwarder for alert delivery, and removes the hook on exit.
    Equivalent to the macOS launcher script and the Linux systemd
    ExecStartPost/ExecStopPost hooks.
#>
param(
    [string]$Prefix = (Join-Path $env:USERPROFILE '.coding-agents-kit')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$FalcoExe = Join-Path $Prefix 'bin\falco.exe'
$ForwarderExe = Join-Path $Prefix 'bin\stdout-forwarder.exe'
$CtlExe = Join-Path $Prefix 'bin\coding-agents-kit-ctl.exe'
$FalcoConfig = Join-Path $Prefix 'config\falco.yaml'
$LogDir = Join-Path $Prefix 'log'
$StderrLog = Join-Path $LogDir 'falco.err'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Read http_port from plugin config to know where to forward alerts
$httpPort = 2802
$pluginConfig = Join-Path $Prefix 'config\falco.coding_agents_plugin.yaml'
if (Test-Path $pluginConfig) {
    foreach ($line in Get-Content $pluginConfig) {
        if ($line -match 'http_port:\s*(\d+)') { $httpPort = [int]$Matches[1]; break }
    }
}

# Register hook before starting Falco
if (Test-Path $CtlExe) {
    & $CtlExe hook add 2>$null
}

# Write a batch file for the pipeline (falco | stdout-forwarder)
$batchFile = Join-Path $LogDir 'run-falco.cmd'
@"
@echo off
"$FalcoExe" -U -c "$FalcoConfig" 2>"$StderrLog" | "$ForwarderExe" http://127.0.0.1:$httpPort
"@ | Set-Content $batchFile -Encoding ASCII

$pipelineProcess = $null

try {
    # Start the pipeline
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = "/c `"$batchFile`""
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = Join-Path $Prefix 'bin'
    $pipelineProcess = [System.Diagnostics.Process]::Start($psi)

    # Wait for Falco to exit (blocks until the pipeline ends)
    $pipelineProcess.WaitForExit()
}
finally {
    # Kill the entire process tree on exit
    if ($pipelineProcess -and -not $pipelineProcess.HasExited) {
        & taskkill /F /T /PID $pipelineProcess.Id 2>$null
    }

    # Remove hook
    if (Test-Path $CtlExe) {
        & $CtlExe hook remove 2>$null
    }
}
