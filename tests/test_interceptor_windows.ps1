#Requires -Version 5.1
<#
.SYNOPSIS
    Integration tests for the interceptor on Windows.
    Port of test_interceptor.sh using TCP mock broker.

.DESCRIPTION
    Requires: python3, built interceptor binary.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$Hook = Join-Path $RootDir 'hooks\claude-code\target\release\claude-interceptor.exe'
$MockBroker = Join-Path $ScriptDir 'mock_broker_uds.ps1'

# Check prerequisites
if (-not (Test-Path $Hook)) {
    Write-Error "Interceptor not found at $Hook. Build with: cargo build --release"
    exit 1
}

$PASS = 0
$FAIL = 0

function Run-Test {
    param(
        [string]$Mode,
        [string]$InputJson,
        [int]$TimeoutMs = 5000,
        [hashtable]$ExtraEnv = @{}
    )

    # Use a unique socket path per test
    $sockPath = Join-Path $env:TEMP "cak-test-$PID-$([guid]::NewGuid().ToString('N').Substring(0,8)).sock"

    # Start mock broker (PowerShell subprocess)
    $brokerPsi = New-Object System.Diagnostics.ProcessStartInfo
    $brokerPsi.FileName = 'powershell.exe'
    $brokerPsi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$MockBroker`" -SocketPath `"$sockPath`" -Mode $Mode"
    $brokerPsi.UseShellExecute = $false
    $brokerPsi.RedirectStandardOutput = $true
    $brokerPsi.RedirectStandardError = $true
    $brokerPsi.CreateNoWindow = $true
    $broker = [System.Diagnostics.Process]::Start($brokerPsi)

    # Wait for READY signal
    $ready = $broker.StandardOutput.ReadLine()
    if (-not $ready -or -not $ready.StartsWith('READY')) {
        $stderr = $broker.StandardError.ReadToEnd()
        try { $broker.Kill() } catch {}
        return "ERROR: broker did not start ($stderr)"
    }

    Start-Sleep -Milliseconds 50

    $hookPsi = New-Object System.Diagnostics.ProcessStartInfo
    $hookPsi.FileName = $Hook
    $hookPsi.UseShellExecute = $false
    $hookPsi.RedirectStandardInput = $true
    $hookPsi.RedirectStandardOutput = $true
    $hookPsi.RedirectStandardError = $true
    $hookPsi.CreateNoWindow = $true
    $hookPsi.EnvironmentVariables['CODING_AGENTS_KIT_SOCKET'] = $sockPath
    foreach ($kv in $ExtraEnv.GetEnumerator()) {
        $hookPsi.EnvironmentVariables[$kv.Key] = $kv.Value
    }

    $hookProc = [System.Diagnostics.Process]::Start($hookPsi)
    $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($InputJson)
    $hookProc.StandardInput.BaseStream.Write($inputBytes, 0, $inputBytes.Length)
    $hookProc.StandardInput.BaseStream.Flush()
    $hookProc.StandardInput.Dispose()

    $stdoutTask = $hookProc.StandardOutput.ReadToEndAsync()
    $stderrTask = $hookProc.StandardError.ReadToEndAsync()
    [void]$hookProc.WaitForExit($TimeoutMs)
    if (-not $hookProc.HasExited) {
        try { $hookProc.Kill() } catch {}
        [void]$hookProc.WaitForExit(2000)
    }
    $output = $stdoutTask.GetAwaiter().GetResult()
    $hookStderr = $stderrTask.GetAwaiter().GetResult()
    $hookExit = $hookProc.ExitCode

    try { if (-not $broker.HasExited) { $broker.Kill() } } catch {}
    try { [void]$broker.WaitForExit(2000) } catch {}
    Remove-Item $sockPath -Force -ErrorAction SilentlyContinue

    Write-Output $output
}

function Run-HookOnly {
    param(
        [string]$InputJson,
        [string]$SocketAddr = "$env:TEMP\cak-nonexistent-$PID.sock"
    )

    $hookPsi = New-Object System.Diagnostics.ProcessStartInfo
    $hookPsi.FileName = $Hook
    $hookPsi.UseShellExecute = $false
    $hookPsi.RedirectStandardInput = $true
    $hookPsi.RedirectStandardOutput = $true
    $hookPsi.RedirectStandardError = $true
    $hookPsi.CreateNoWindow = $true
    $hookPsi.EnvironmentVariables['CODING_AGENTS_KIT_SOCKET'] = $SocketAddr

    $proc = [System.Diagnostics.Process]::Start($hookPsi)
    $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($InputJson)
    if ($inputBytes.Length -gt 0) {
        $proc.StandardInput.BaseStream.Write($inputBytes, 0, $inputBytes.Length)
    }
    $proc.StandardInput.Close()

    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    [void]$proc.WaitForExit(5000)
    if (-not $proc.HasExited) {
        try { $proc.Kill() } catch {}
        [void]$proc.WaitForExit(2000)
    }
    $output = $stdoutTask.GetAwaiter().GetResult()
    $exitCode = $proc.ExitCode

    return @{
        Output = $output
        ExitCode = $exitCode
    }
}

function Assert-Contains {
    param([string]$Output, [string]$Expected, [string]$TestName)
    if ($Output.Contains($Expected)) {
        Write-Host "  PASS: $TestName"
        $script:PASS++
    } else {
        Write-Host "  FAIL: $TestName"
        Write-Host "    expected: contains '$Expected'"
        Write-Host "    got: $Output"
        $script:FAIL++
    }
}

$SAMPLE = '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"test-sess","cwd":"C:\\Users\\test","tool_use_id":"toolu_test123"}'

# ------------------------------------------------------------------
Write-Host "=== Allow verdict ==="
$out = Run-Test -Mode allow -Input $SAMPLE
Assert-Contains $out '"permissionDecision":"allow"' "allow verdict"

Write-Host "=== Deny verdict ==="
$out = Run-Test -Mode deny -Input $SAMPLE
Assert-Contains $out '"permissionDecision":"deny"' "deny verdict"
Assert-Contains $out 'blocked by test rule' "deny reason"

Write-Host "=== Ask verdict ==="
$out = Run-Test -Mode ask -Input $SAMPLE
Assert-Contains $out '"permissionDecision":"ask"' "ask verdict"
Assert-Contains $out 'requires confirmation' "ask reason"

Write-Host "=== Broker unreachable (fail-closed) ==="
$result = Run-HookOnly -Input $SAMPLE -SocketAddr '127.0.0.1:19999'
Assert-Contains $result.Output '"permissionDecision":"deny"' "fail-closed deny"

Write-Host "=== Bad JSON response ==="
$out = Run-Test -Mode bad_json -Input $SAMPLE
Assert-Contains $out '"permissionDecision":"deny"' "bad_json deny"

Write-Host "=== Wrong ID response ==="
$out = Run-Test -Mode wrong_id -Input $SAMPLE
Assert-Contains $out '"permissionDecision":"deny"' "wrong_id deny"

Write-Host "=== Timeout ==="
$out = Run-Test -Mode 'slow:3' -Input $SAMPLE -ExtraEnv @{ CODING_AGENTS_KIT_TIMEOUT_MS = '200' }
Assert-Contains $out '"permissionDecision":"deny"' "timeout deny"

Write-Host "=== Broker closes connection ==="
$out = Run-Test -Mode close -Input $SAMPLE
Assert-Contains $out '"permissionDecision":"deny"' "close deny"

Write-Host "=== Empty stdin ==="
$result = Run-HookOnly -Input ''
if ($result.ExitCode -eq 2) {
    Write-Host "  PASS: empty stdin exit 2"
    $PASS++
} else {
    Write-Host "  FAIL: empty stdin exit 2"
    Write-Host "    expected: exit 2, got: exit $($result.ExitCode)"
    $FAIL++
}

Write-Host "=== Malformed JSON ==="
$result = Run-HookOnly -Input 'not json'
if ($result.ExitCode -eq 2) {
    Write-Host "  PASS: malformed JSON exit 2"
    $PASS++
} else {
    Write-Host "  FAIL: malformed JSON exit 2"
    Write-Host "    expected: exit 2, got: exit $($result.ExitCode)"
    $FAIL++
}

Write-Host "=== Missing tool_name (no broker) ==="
$result = Run-HookOnly -Input '{"hook_event_name":"PreToolUse","tool_input":{}}'
Assert-Contains $result.Output '"permissionDecision":"deny"' "missing tool_name deny (no broker)"

Write-Host "=== Write tool path ==="
$writeInput = '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"C:\\Users\\test\\file.txt","content":"hello"},"session_id":"s1","cwd":"C:\\Users\\test","tool_use_id":"t2"}'
$out = Run-Test -Mode allow -Input $writeInput
Assert-Contains $out '"permissionDecision":"allow"' "write tool"

Write-Host "=== MCP tool ==="
$mcpInput = '{"hook_event_name":"PreToolUse","tool_name":"mcp__github__create_issue","tool_input":{"title":"test"},"session_id":"s1","cwd":"C:\\Users\\test","tool_use_id":"t3"}'
$out = Run-Test -Mode allow -Input $mcpInput
Assert-Contains $out '"permissionDecision":"allow"' "MCP tool"

Write-Host "=== Large tool_input ==="
$largeCmd = 'x' * 60000
$largeInput = "{`"hook_event_name`":`"PreToolUse`",`"tool_name`":`"Bash`",`"tool_input`":{`"command`":`"$largeCmd`"},`"session_id`":`"s1`",`"cwd`":`"C:\\Users\\test`",`"tool_use_id`":`"t4`"}"
$out = Run-Test -Mode allow -Input $largeInput
Assert-Contains $out '"permissionDecision":"allow"' "large input"

Write-Host "=== JSON escape in command ==="
$escInput = '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo \"hello world\""},"session_id":"s1","cwd":"C:\\Users\\test","tool_use_id":"t6"}'
$out = Run-Test -Mode allow -Input $escInput
Assert-Contains $out '"permissionDecision":"allow"' "escaped command"

# ------------------------------------------------------------------
Write-Host ""
Write-Host "================================"
Write-Host "Results: $PASS passed, $FAIL failed"
Write-Host "================================"

exit $(if ($FAIL -eq 0) { 0 } else { 1 })
