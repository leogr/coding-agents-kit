#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end tests for the coding-agents-kit pipeline on Windows.
    Port of test_e2e.sh with stdout forwarder for alert delivery.

.DESCRIPTION
    Starts Falco with the plugin, writes rules, sends test events via
    the interceptor, and validates verdicts. Uses a stdout forwarder to
    bridge Falco's stdout_output to the plugin's HTTP alert receiver.

    Requires: built Falco, plugin DLL, interceptor.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$Hook = Join-Path $RootDir 'hooks\claude-code\target\release\claude-interceptor.exe'
$PluginDll = Join-Path $RootDir 'plugins\coding-agent-plugin\target\release\coding_agent_plugin.dll'
$FalcoExe = Join-Path $RootDir 'build\falco-0.43.0-windows-arm64\falco.exe'
$Forwarder = Join-Path $ScriptDir 'stdout_forwarder.ps1'

# Use a test-specific temp directory
$E2eDir = Join-Path $RootDir "build\e2e-$PID"
New-Item -ItemType Directory -Force -Path $E2eDir | Out-Null
$BrokerAddr = '127.0.0.1:2803'
$HttpPort = 19000 + ($PID % 1000)
$FalcoLog = Join-Path $E2eDir 'falco-stdout.log'
$PASS = 0
$FAIL = 0

# --- Preflight ---
foreach ($f in @($Hook, $PluginDll, $FalcoExe)) {
    if (-not (Test-Path $f)) {
        Write-Error "Not found: $f"
        exit 1
    }
}

# --- Rules ---
$RulesDir = Join-Path $E2eDir 'rules'
New-Item -ItemType Directory -Force -Path $RulesDir | Out-Null

# Deny rules adapted for Windows paths
@'
- rule: Deny rm -rf
  desc: Block dangerous rm -rf commands
  condition: tool.name = "Bash" and tool.input_command contains "rm -rf"
  output: "DENY id=%correlation.id cmd=%tool.input_command"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Deny writes to system dirs
  desc: Block writes to Windows system directories
  condition: tool.name in ("Write", "Edit") and tool.real_file_path startswith "C:/Windows"
  output: "DENY id=%correlation.id path=%tool.real_file_path"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Ask write outside cwd
  desc: Require confirmation for writes outside working directory
  condition: tool.name in ("Write", "Edit") and not tool.real_file_path startswith val(agent.real_cwd)
  output: "ASK id=%correlation.id path=%tool.real_file_path cwd=%agent.real_cwd"
  priority: WARNING
  source: coding_agent
  tags: [coding_agent_ask]

- rule: Deny reading sensitive paths
  desc: Block reads from sensitive paths
  condition: tool.name = "Read" and (tool.real_file_path startswith "C:/Windows/System32/config" or tool.real_file_path contains "/.ssh/")
  output: "Falco blocked reading %tool.real_file_path because it is a sensitive path"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]
'@ | Set-Content (Join-Path $RulesDir 'deny.yaml') -Encoding UTF8

@'
- rule: Coding Agent Event Seen
  desc: Catch-all rule signaling evaluation complete
  condition: correlation.id > 0
  output: "id=%correlation.id"
  priority: DEBUG
  source: coding_agent
  tags: [coding_agent_seen]
'@ | Set-Content (Join-Path $RulesDir 'seen.yaml') -Encoding UTF8

# --- Helpers ---
$falcoProcess = $null
$forwarderProcess = $null

function Cleanup {
    if ($script:forwarderProcess -and -not $script:forwarderProcess.HasExited) {
        try { $script:forwarderProcess.Kill() } catch {}
    }
    if ($script:falcoProcess -and -not $script:falcoProcess.HasExited) {
        try { $script:falcoProcess.Kill() } catch {}
    }
    Start-Sleep -Milliseconds 500
    Remove-Item $E2eDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Start-Falco {
    param([string]$Mode = 'enforcement')

    # Clean up any previous Falco
    if ($script:falcoProcess -and -not $script:falcoProcess.HasExited) {
        try { $script:falcoProcess.Kill() } catch {}
    }

    Remove-Item $FalcoLog -Force -ErrorAction SilentlyContinue
    '' | Set-Content $FalcoLog -Encoding UTF8  # create empty file

    $initConfig = "{`"socket_path`":`"$BrokerAddr`",`"http_port`":$HttpPort,`"mode`":`"$Mode`"}"
    $denyRules = (Join-Path $RulesDir 'deny.yaml') -replace '\\', '/'
    $seenRules = (Join-Path $RulesDir 'seen.yaml') -replace '\\', '/'
    # Use just the DLL filename — Falco prepends ./ to the path, so absolute paths break.
    # The DLL must be copied next to falco.exe before running.
    $pluginPath = 'coding_agent_plugin.dll'

    # Create a minimal base config (Falco requires -c even with -o overrides)
    $baseConfig = Join-Path $E2eDir 'falco.yaml'
    "engine:`n  kind: nodriver" | Set-Content $baseConfig -Encoding UTF8

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FalcoExe
    $psi.Arguments = @(
        '-c', $baseConfig,
        '-o', 'config_files=',
        '-o', "plugins[0].name=coding_agent",
        '-o', "plugins[0].library_path=$pluginPath",
        '-o', "plugins[0].init_config=$initConfig",
        '-o', 'load_plugins[0]=coding_agent',
        '-o', "rules_files[0]=$denyRules",
        '-o', "rules_files[1]=$seenRules",
        '-o', 'json_output=true',
        '-o', 'json_include_message_property=true',
        '-o', 'json_include_output_property=false',
        '-o', 'json_include_output_fields_property=true',
        '-o', 'json_include_tags_property=true',
        '-o', 'rule_matching=all',
        '-o', 'priority=debug',
        '-o', 'stdout_output.enabled=true',
        '-o', 'syslog_output.enabled=false',
        '--disable-source', 'syscall'
    ) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    # Launch Falco with stdout captured, and a separate forwarder script that
    # reads from a pipe and POSTs each JSON alert line to the HTTP server.
    # We use a PowerShell wrapper that reads Falco stdout line-by-line and
    # forwards via HTTP, avoiding buffering issues with cmd.exe redirection.
    $falcoArgs = $psi.Arguments
    $forwarderScript = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$psi = New-Object System.Diagnostics.ProcessStartInfo
`$psi.FileName = '$($FalcoExe -replace "'", "''")'
`$psi.Arguments = '$($falcoArgs -replace "'", "''")'
`$psi.UseShellExecute = `$false
`$psi.RedirectStandardOutput = `$true
`$psi.RedirectStandardError = `$true
`$psi.CreateNoWindow = `$true
`$proc = [System.Diagnostics.Process]::Start(`$psi)
while (`$null -ne (`$line = `$proc.StandardOutput.ReadLine())) {
    `$line = `$line.Trim()
    if (`$line.Length -eq 0 -or -not `$line.StartsWith('{')) { continue }
    try {
        `$b = [System.Text.Encoding]::UTF8.GetBytes(`$line)
        `$r = [System.Net.HttpWebRequest]::Create('http://127.0.0.1:$HttpPort')
        `$r.Method = 'POST'; `$r.ContentType = 'application/json'; `$r.ContentLength = `$b.Length; `$r.Timeout = 2000
        `$s = `$r.GetRequestStream(); `$s.Write(`$b, 0, `$b.Length); `$s.Close()
        `$resp = `$r.GetResponse(); `$resp.Close()
    } catch {}
}
`$proc.WaitForExit()
"@
    $wrapperPath = Join-Path $E2eDir 'falco-wrapper.ps1'
    Set-Content $wrapperPath $forwarderScript -Encoding UTF8

    $wrapperPsi = New-Object System.Diagnostics.ProcessStartInfo
    $wrapperPsi.FileName = 'powershell.exe'
    $wrapperPsi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$wrapperPath`""
    $wrapperPsi.UseShellExecute = $false
    $wrapperPsi.CreateNoWindow = $true
    $script:falcoProcess = [System.Diagnostics.Process]::Start($wrapperPsi)

    # Wait for broker TCP port to be listening
    $retries = 0
    while ($retries -lt 40) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect('127.0.0.1', 2803)
            $tcp.Close()
            break
        } catch {
            Start-Sleep -Milliseconds 250
            $retries++
        }
    }

    if ($retries -ge 40) {
        Write-Host "ERROR: Falco broker did not start (TCP 2803 not listening)"
        $stderr = $script:falcoProcess.StandardError.ReadToEnd()
        Write-Host "Falco stderr: $stderr"
        return $false
    }

    # Extra wait for HTTP server
    Start-Sleep -Milliseconds 500
    return $true
}

function Run-Hook {
    param([string]$JsonInput)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Hook
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables['CODING_AGENTS_KIT_SOCKET'] = $BrokerAddr
    $psi.EnvironmentVariables['CODING_AGENTS_KIT_TIMEOUT_MS'] = '8000'

    $proc = [System.Diagnostics.Process]::Start($psi)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($JsonInput)
    $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $proc.StandardInput.BaseStream.Flush()
    $proc.StandardInput.Dispose()

    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    [void]$proc.WaitForExit(10000)
    if (-not $proc.HasExited) { try { $proc.Kill() } catch {} }

    return $stdoutTask.GetAwaiter().GetResult()
}

function Make-InputJson {
    param(
        [string]$ToolName,
        [string]$ToolInputJson,
        [string]$Cwd = 'C:\Users\test\project',
        [string]$Id = "toolu_$([guid]::NewGuid().ToString('N').Substring(0,12))"
    )
    $cwdEsc = $Cwd -replace '\\', '\\'
    return "{`"hook_event_name`":`"PreToolUse`",`"tool_name`":`"$ToolName`",`"tool_input`":$ToolInputJson,`"session_id`":`"e2e-test`",`"cwd`":`"$cwdEsc`",`"tool_use_id`":`"$Id`"}"
}

function Assert-Decision {
    param([string]$Output, [string]$Expected, [string]$TestName)
    if ($Output.Contains("`"permissionDecision`":`"$Expected`"")) {
        Write-Host "  PASS: $TestName"
        $script:PASS++
    } else {
        Write-Host "  FAIL: $TestName"
        Write-Host "    expected: decision=$Expected"
        Write-Host "    got: $Output"
        $script:FAIL++
    }
}

function Assert-ReasonContains {
    param([string]$Output, [string]$Needle, [string]$TestName)
    if ($Output.Contains($Needle)) {
        Write-Host "  PASS: $TestName"
        $script:PASS++
    } else {
        Write-Host "  FAIL: $TestName"
        Write-Host "    expected: reason contains '$Needle'"
        Write-Host "    got: $Output"
        $script:FAIL++
    }
}

# ===================================================================
# Start Falco
# ===================================================================

Write-Host "Starting Falco with plugin..."
$ok = Start-Falco -Mode 'enforcement'
if (-not $ok) {
    Write-Host "FATAL: Could not start Falco"
    Cleanup
    exit 1
}
Write-Host "Falco running (broker=$BrokerAddr, http=$HttpPort)"
Write-Host ""

# ===================================================================
# Enforcement Tests
# ===================================================================

Write-Host "=== Deny: rm -rf ==="
$out = Run-Hook (Make-InputJson 'Bash' '{"command":"rm -rf /"}' 'C:\Users\test' 'toolu_rmrf1')
Assert-Decision $out 'deny' 'rm -rf denied'
Assert-ReasonContains $out 'Deny rm -rf' 'deny reason mentions rule'

Write-Host "=== Allow: safe command ==="
$out = Run-Hook (Make-InputJson 'Bash' '{"command":"ls -la"}' 'C:\Users\test' 'toolu_ls1')
Assert-Decision $out 'allow' 'ls allowed'

Write-Host "=== Allow: echo command ==="
$out = Run-Hook (Make-InputJson 'Bash' '{"command":"echo hello"}' 'C:\Users\test' 'toolu_echo1')
Assert-Decision $out 'allow' 'echo allowed'

Write-Host "=== Deny: write to Windows system dir ==="
$out = Run-Hook (Make-InputJson 'Write' '{"file_path":"C:\\Windows\\System32\\test.txt","content":"x"}' 'C:\Users\test' 'toolu_syswrite1')
Assert-Decision $out 'deny' 'write to C:\Windows denied'

Write-Host "=== Ask: write outside cwd ==="
$out = Run-Hook (Make-InputJson 'Write' '{"file_path":"C:\\Users\\other\\file.txt","content":"x"}' 'C:\Users\test\project' 'toolu_outside1')
Assert-Decision $out 'ask' 'write outside cwd asks'

Write-Host "=== Allow: write inside cwd ==="
$out = Run-Hook (Make-InputJson 'Write' '{"file_path":"C:\\Users\\test\\project\\file.txt","content":"x"}' 'C:\Users\test\project' 'toolu_inside1')
Assert-Decision $out 'allow' 'write inside cwd allowed'

Write-Host "=== Allow: Read tool ==="
$out = Run-Hook (Make-InputJson 'Read' '{"file_path":"C:\\Users\\test\\readme.txt"}' 'C:\Users\test' 'toolu_read1')
Assert-Decision $out 'allow' 'read allowed'

Write-Host "=== Deny: read sensitive path ==="
$out = Run-Hook (Make-InputJson 'Read' '{"file_path":"C:\\Windows\\System32\\config\\SAM"}' 'C:\Users\test' 'toolu_readsam1')
Assert-Decision $out 'deny' 'read SAM denied'

Write-Host "=== Allow: Grep tool ==="
$out = Run-Hook (Make-InputJson 'Grep' '{"pattern":"foo","path":"C:\\Users\\test"}' 'C:\Users\test' 'toolu_grep1')
Assert-Decision $out 'allow' 'grep allowed'

Write-Host "=== Allow: MCP tool ==="
$out = Run-Hook (Make-InputJson 'mcp__github__get_issue' '{"number":42}' 'C:\Users\test' 'toolu_mcp1')
Assert-Decision $out 'allow' 'MCP tool allowed'

Write-Host "=== Deny: read .ssh ==="
$out = Run-Hook (Make-InputJson 'Read' '{"file_path":"C:\\Users\\test\\.ssh\\id_rsa"}' 'C:\Users\test' 'toolu_ssh1')
Assert-Decision $out 'deny' 'read .ssh denied'

# ===================================================================
# Results
# ===================================================================

Write-Host ""
Write-Host "================================"
Write-Host "Results: $PASS passed, $FAIL failed"
Write-Host "================================"

Cleanup
exit $(if ($FAIL -eq 0) { 0 } else { 1 })
