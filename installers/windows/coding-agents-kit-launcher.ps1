#Requires -Version 5.1
<#
.SYNOPSIS
    Launches the coding-agents-kit Falco service on Windows.

.DESCRIPTION
    Registers the Claude Code hook, starts Falco in the foreground,
    and removes the hook on exit. Equivalent to the macOS launcher script
    and the Linux systemd ExecStartPost/ExecStopPost hooks.
#>
param(
    [string]$Prefix = (Join-Path $env:USERPROFILE '.coding-agents-kit')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$FalcoExe = Join-Path $Prefix 'bin\falco.exe'
$CtlExe = Join-Path $Prefix 'bin\coding-agents-kit-ctl.exe'
$FalcoConfig = Join-Path $Prefix 'config\falco.yaml'
$LogDir = Join-Path $Prefix 'log'
$StdoutLog = Join-Path $LogDir 'falco.log'
$StderrLog = Join-Path $LogDir 'falco.err'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Register hook before starting Falco
if (Test-Path $CtlExe) {
    & $CtlExe hook add 2>$null
}

# Cleanup function: remove hook on exit
$cleanup = {
    if (Test-Path $CtlExe) {
        & $CtlExe hook remove 2>$null
    }
}

try {
    # Register cleanup for Ctrl+C / process termination
    Register-EngineEvent PowerShell.Exiting -Action $cleanup | Out-Null

    # Start Falco in the foreground, redirect output to log files
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FalcoExe
    $psi.Arguments = "-U -c `"$FalcoConfig`" --disable-source syscall"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::Start($psi)

    # Async read stdout/stderr to log files
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    $process.WaitForExit()

    # Write logs
    [System.IO.File]::WriteAllText($StdoutLog, $stdoutTask.Result)
    [System.IO.File]::WriteAllText($StderrLog, $stderrTask.Result)
}
finally {
    & $cleanup
}
