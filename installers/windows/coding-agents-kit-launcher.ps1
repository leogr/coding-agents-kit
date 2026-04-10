#Requires -Version 5.1
<#
.SYNOPSIS
    Launches the coding-agents-kit Falco service on Windows.

.DESCRIPTION
    Registers the Claude Code hook, starts Falco with http_output for
    alert delivery, and removes the hook on exit.
    Equivalent to the macOS launcher script and the Linux systemd
    ExecStartPost/ExecStopPost hooks.
#>
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'coding-agents-kit')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$FalcoExe = Join-Path $Prefix 'bin\falco.exe'
$CtlExe = Join-Path $Prefix 'bin\coding-agents-kit-ctl.exe'
$FalcoConfig = Join-Path $Prefix 'config\falco.yaml'
$LogDir = Join-Path $Prefix 'log'
$StderrLog = Join-Path $LogDir 'falco.err'
$StdoutLog = Join-Path $LogDir 'falco.log'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Register hook before starting Falco (suppress stderr to avoid ErrorActionPreference=Stop)
if (Test-Path $CtlExe) {
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $CtlExe hook add 2>&1 | Out-Null
    $ErrorActionPreference = $prevPref
}

$falcoProcess = $null

try {
    # Start Falco directly (http_output delivers alerts to the plugin HTTP server)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FalcoExe
    $psi.Arguments = "-U -c `"$FalcoConfig`" --disable-source syscall"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = Join-Path $Prefix 'bin'
    $falcoProcess = [System.Diagnostics.Process]::Start($psi)

    # Drain stdout/stderr asynchronously to prevent OS pipe buffer deadlock.
    # Even with stdout_output disabled, Falco may write startup messages.
    $stdoutJob = Register-ObjectEvent -InputObject $falcoProcess -EventName OutputDataReceived -Action {
        if ($EventArgs.Data) { $EventArgs.Data | Out-File -Append -FilePath $Event.MessageData -Encoding UTF8 }
    } -MessageData $StdoutLog
    $stderrJob = Register-ObjectEvent -InputObject $falcoProcess -EventName ErrorDataReceived -Action {
        if ($EventArgs.Data) { $EventArgs.Data | Out-File -Append -FilePath $Event.MessageData -Encoding UTF8 }
    } -MessageData $StderrLog
    $falcoProcess.BeginOutputReadLine()
    $falcoProcess.BeginErrorReadLine()

    # Wait for Falco to exit
    $falcoProcess.WaitForExit()
}
finally {
    # Clean up event subscriptions
    if ($stdoutJob) { Unregister-Event -SourceIdentifier $stdoutJob.Name -ErrorAction SilentlyContinue }
    if ($stderrJob) { Unregister-Event -SourceIdentifier $stderrJob.Name -ErrorAction SilentlyContinue }

    # Kill Falco if still running
    if ($falcoProcess -and -not $falcoProcess.HasExited) {
        try { $falcoProcess.Kill() } catch {}
    }

    # Remove hook (suppress errors)
    if (Test-Path $CtlExe) {
        $ErrorActionPreference = 'Continue'
        & $CtlExe hook remove 2>&1 | Out-Null
    }
}
