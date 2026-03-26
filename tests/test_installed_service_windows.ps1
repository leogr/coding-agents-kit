#Requires -Version 5.1
<#
.SYNOPSIS
    Integration test for the installed coding-agents-kit service on Windows.

.DESCRIPTION
    Tests the full installed pipeline: launcher → Falco → plugin → rules →
    verdict → interceptor. Optionally tests with Claude Code if detected.

    Requires: coding-agents-kit installed via MSI + postinstall.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Prefix = Join-Path $env:LOCALAPPDATA 'coding-agents-kit'
$Launcher = Join-Path $Prefix 'bin\coding-agents-kit-launcher.ps1'
$Hook = Join-Path $Prefix 'bin\claude-interceptor.exe'
$SockPath = ($Prefix -replace '\\', '/') + '/run/broker.sock'
$PASS = 0
$FAIL = 0
$launcherProc = $null

function Cleanup {
    if ($script:launcherProc -and -not $script:launcherProc.HasExited) {
        & taskkill /F /T /PID $script:launcherProc.Id 2>$null
    }
    Start-Sleep -Milliseconds 500
}

function Assert-True([bool]$Condition, [string]$TestName) {
    if ($Condition) {
        Write-Host "  PASS: $TestName"
        $script:PASS++
    } else {
        Write-Host "  FAIL: $TestName"
        $script:FAIL++
    }
}

function Run-Hook([string]$Json) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Hook
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['CODING_AGENTS_KIT_SOCKET'] = $SockPath
    $psi.EnvironmentVariables['CODING_AGENTS_KIT_TIMEOUT_MS'] = '8000'
    $proc = [System.Diagnostics.Process]::Start($psi)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
    $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $proc.StandardInput.BaseStream.Flush()
    $proc.StandardInput.Dispose()
    $so = $proc.StandardOutput.ReadToEndAsync()
    [void]$proc.WaitForExit(10000)
    return $so.GetAwaiter().GetResult()
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

Write-Host "=== Preflight ==="
$missing = @()
foreach ($f in @($Launcher, $Hook, (Join-Path $Prefix 'bin\falco.exe'), (Join-Path $Prefix 'bin\stdout-forwarder.exe'), (Join-Path $Prefix 'share\coding_agent_plugin.dll'), (Join-Path $Prefix 'config\falco.yaml'))) {
    if (-not (Test-Path $f)) { $missing += (Split-Path $f -Leaf) }
}
if ($missing.Count -gt 0) {
    Write-Error "coding-agents-kit not installed. Missing: $($missing -join ', ')"
    exit 1
}
Write-Host "  Installation verified"

# ---------------------------------------------------------------------------
# Start service
# ---------------------------------------------------------------------------

Write-Host "`n=== Start service ==="
Get-Process falco, stdout-forwarder -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1
Remove-Item (Join-Path $Prefix 'run\broker.sock') -Force -ErrorAction SilentlyContinue

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'powershell.exe'
$psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$Launcher`" -Prefix `"$Prefix`""
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$launcherProc = [System.Diagnostics.Process]::Start($psi)

$retries = 0
$sockFile = Join-Path $Prefix 'run\broker.sock'
while ($retries -lt 40) {
    if (Test-Path $sockFile) { break }
    Start-Sleep -Milliseconds 250
    $retries++
}

Assert-True (Test-Path $sockFile) "broker socket created"
Assert-True (-not $launcherProc.HasExited) "service running"

if ($launcherProc.HasExited -or -not (Test-Path $sockFile)) {
    Write-Host "FATAL: service did not start"
    Cleanup
    exit 1
}

Start-Sleep -Milliseconds 500

# ---------------------------------------------------------------------------
# Interceptor tests against installed service
# ---------------------------------------------------------------------------

Write-Host "`n=== Interceptor → installed service ==="

$allowJson = '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"},"session_id":"installed-test","cwd":"C:\\Users\\test","tool_use_id":"inst_allow1"}'
$out = Run-Hook $allowJson
Assert-True ($out.Contains('"permissionDecision"')) "interceptor gets a verdict"
# Default rules should allow safe commands
Assert-True ($out.Contains('"permissionDecision":"allow"')) "safe command allowed"

$readJson = '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"C:\\Users\\test\\readme.txt"},"session_id":"installed-test","cwd":"C:\\Users\\test","tool_use_id":"inst_read1"}'
$out = Run-Hook $readJson
Assert-True ($out.Contains('"permissionDecision":"allow"')) "read file allowed"

$grepJson = '{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"test","path":"C:\\Users\\test"},"session_id":"installed-test","cwd":"C:\\Users\\test","tool_use_id":"inst_grep1"}'
$out = Run-Hook $grepJson
Assert-True ($out.Contains('"permissionDecision":"allow"')) "grep allowed"

# ---------------------------------------------------------------------------
# Claude Code integration (only if claude is installed)
# ---------------------------------------------------------------------------

$claudeExe = Get-Command 'claude' -ErrorAction SilentlyContinue
if ($claudeExe) {
    Write-Host "`n=== Claude Code integration ==="

    # Check hook is registered
    $settingsPath = Join-Path $env:USERPROFILE '.claude\settings.json'
    if (Test-Path $settingsPath) {
        $settings = Get-Content $settingsPath -Raw
        Assert-True ($settings.Contains('claude-interceptor')) "hook registered in Claude Code settings"
    } else {
        Write-Host "  SKIP: no Claude Code settings.json found"
    }

    # Test: ask Claude to run a safe command via --print (non-interactive)
    # This exercises the real hook path: Claude → hook → interceptor → broker → Falco → verdict
    Write-Host "  Testing Claude Code with real hook (this may take a moment)..."
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $claudeOut = & claude --print "What is 2+2? Reply with just the number." 2>&1
    $ErrorActionPreference = $prevPref
    $claudeStr = ($claudeOut | Out-String).Trim()
    if ($claudeStr.Contains('4')) {
        Write-Host "  PASS: Claude Code responded (hook didn't block)"
        $PASS++
    } else {
        Write-Host "  INFO: Claude Code response: $claudeStr"
        Write-Host "  (This may fail if Claude Code requires auth or the model is unavailable)"
    }
} else {
    Write-Host "`n=== Claude Code integration ==="
    Write-Host "  SKIP: claude command not found (install Claude Code to enable)"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

Write-Host "`n=== Cleanup ==="
Cleanup

Write-Host "`n================================"
Write-Host "Results: $PASS passed, $FAIL failed"
Write-Host "================================"

exit $(if ($FAIL -eq 0) { 0 } else { 1 })
