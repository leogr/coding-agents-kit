#Requires -Version 5.1
<#
.SYNOPSIS
    Post-installation setup for coding-agents-kit on Windows.

.DESCRIPTION
    Called by the MSI custom action after files are deployed.
    Generates Falco config with resolved paths, registers the Claude Code
    hook, and sets up auto-start via Registry Run key.
#>
param(
    [string]$Prefix = (Join-Path $env:USERPROFILE '.coding-agents-kit')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BinDir = Join-Path $Prefix 'bin'
$ConfigDir = Join-Path $Prefix 'config'
$ShareDir = Join-Path $Prefix 'share'
$RulesDir = Join-Path $Prefix 'rules'
$RunDir = Join-Path $Prefix 'run'
$LogDir = Join-Path $Prefix 'log'

# Ensure runtime directories exist
foreach ($dir in @($RunDir, $LogDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# ---------------------------------------------------------------------------
# Generate falco.yaml with resolved Windows paths
# ---------------------------------------------------------------------------

$falcoYaml = @"
# coding-agents-kit Falco configuration (Windows, auto-generated)
engine:
  kind: nodriver

config_files:
  - $($ConfigDir -replace '\\', '/')/falco.coding_agents_plugin.yaml

stdout_output:
  enabled: true

json_output: true
json_include_output_property: false
json_include_message_property: true
json_include_output_fields_property: true
json_include_tags_property: true

rule_matching: all
priority: debug

watch_config_files: true
"@

Set-Content -Path (Join-Path $ConfigDir 'falco.yaml') -Value $falcoYaml -Encoding UTF8
Write-Host "Generated falco.yaml"

# ---------------------------------------------------------------------------
# Generate plugin config with resolved Windows paths
# ---------------------------------------------------------------------------

$pluginYaml = @"
# coding-agents-kit plugin configuration (Windows, auto-generated)
plugins:
  - name: coding_agent
    library_path: $($ShareDir -replace '\\', '/')/coding_agent_plugin.dll
    init_config:
      mode: enforcement
      socket_path: "127.0.0.1:2803"
      http_port: 2802

load_plugins:
  - coding_agent

rules_files:
  - $($RulesDir -replace '\\', '/')/default/coding_agents_rules.yaml
  - $($RulesDir -replace '\\', '/')/user/
  - $($RulesDir -replace '\\', '/')/seen.yaml

append_output:
  - match:
      source: coding_agent
    extra_output: " | For AI Agents: inform the user that this action was flagged by a Falco security rule | correlation=%correlation.id"
"@

Set-Content -Path (Join-Path $ConfigDir 'falco.coding_agents_plugin.yaml') -Value $pluginYaml -Encoding UTF8
Write-Host "Generated falco.coding_agents_plugin.yaml"

# ---------------------------------------------------------------------------
# Register Claude Code hook
# ---------------------------------------------------------------------------

$ctlExe = Join-Path $BinDir 'coding-agents-kit-ctl.exe'
if (Test-Path $ctlExe) {
    & $ctlExe hook add
}

# ---------------------------------------------------------------------------
# Register auto-start via Registry Run key
# ---------------------------------------------------------------------------

$launcherScript = Join-Path $BinDir 'coding-agents-kit-launcher.ps1'
if (Test-Path $launcherScript) {
    $runCmd = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcherScript`""
    $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name 'CodingAgentsKit' -Value $runCmd
    Write-Host "Registered auto-start"
}

Write-Host "Post-install complete"
