#!/usr/bin/env bash
#
# Bypass tests for sandbox-disable.yaml.
#
# Each section demonstrates an evasion technique against the original 2-rule design.
# All tests run against the HARDENED rules and assert that the bypass is now caught.
# Comments explain the original gap and the fix applied.
#
# Bypasses covered:
#   B1   Edit value-only diff         "enabled":true→false — "sandbox" not in diff strings
#   B2   Numeric zero (Write/Edit)    "enabled":0 — JS falsy, not string "false"
#   B3   settings.local.json          not in original is_agent_sandbox_config path list
#   B4   Gemini "none"/"disabled"     string disable values, not boolean false
#   B5   Null value (Write/Edit)      "enabled":null — JS falsy, no "false" anywhere
#   B6   allowUnsandboxedCommands:1   numeric truthy, not string "true"
#   B7   Bash echo/tee/python write   Write/Edit rule never fires for Bash tool
#   B8   Python capital False         python3 False (capital) bypasses lowercase check
#   B9   Bash null in command         echo '{"sandbox":{"enabled":null}}' (no "false")
#   B10  Bash enabled:0 in command    echo '{"enabled":0}' (no "false", no "sandbox")
#   B11  Bash allowUnsandboxedCommands:1 via Bash
#   B12  sed -i settings              no disable keyword in sed command itself
#   B13  cp pre-crafted settings      no keywords at all in cp command
#   B14  mv pre-crafted settings      same for mv
#   B15  Codex underscore flag        --dangerously_bypass_approvals_and_sandbox
#   B16  GEMINI_SANDBOX=0             numeric zero not in none/false/disabled list
#   B17  dangerouslyDisableSandbox:false  key-only check was a false positive (now fixed)
#
# Requires: Falco 0.43+, built plugin (.so/.dylib), built interceptor.
# Run on EC2 Ubuntu 22.04 or isolated Docker. Do NOT run locally on macOS.
#
# Usage:
#   bash tests/test_sandbox_bypass.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." &>/dev/null && pwd)"

case "$(uname -s)" in
    Darwin) PLUGIN_EXT="dylib" ;;
    *)      PLUGIN_EXT="so" ;;
esac

HOOK="${HOOK:-}"
if [[ -z "$HOOK" ]]; then
    if [[ -x "${ROOT_DIR}/hooks/claude-code/target/release/claude-interceptor" ]]; then
        HOOK="${ROOT_DIR}/hooks/claude-code/target/release/claude-interceptor"
    elif [[ -x "${HOME}/.coding-agents-kit/bin/claude-interceptor" ]]; then
        HOOK="${HOME}/.coding-agents-kit/bin/claude-interceptor"
    fi
fi

PLUGIN_LIB="${PLUGIN_LIB:-}"
if [[ -z "$PLUGIN_LIB" ]]; then
    if [[ -f "${ROOT_DIR}/plugins/coding-agent-plugin/target/release/libcoding_agent_plugin.${PLUGIN_EXT}" ]]; then
        PLUGIN_LIB="${ROOT_DIR}/plugins/coding-agent-plugin/target/release/libcoding_agent_plugin.${PLUGIN_EXT}"
    elif [[ -f "${HOME}/.coding-agents-kit/share/libcoding_agent_plugin.${PLUGIN_EXT}" ]]; then
        PLUGIN_LIB="${HOME}/.coding-agents-kit/share/libcoding_agent_plugin.${PLUGIN_EXT}"
    fi
fi

RULES_FILE="${ROOT_DIR}/rules/default/sandbox-disable.yaml"
SEEN_FILE="${ROOT_DIR}/rules/seen.yaml"

E2E_DIR="${ROOT_DIR}/build/e2e-sandbox-bypass-$$"
mkdir -p "$E2E_DIR"
SOCK="${E2E_DIR}/broker.sock"
HTTP_PORT=$((24000 + ($$ % 1000)))
PASS=0
FAIL=0
FALCO_PID=""

for bin in falco "$HOOK"; do
    if [[ -z "$bin" ]] || ( [[ ! -x "$bin" ]] && ! command -v "$bin" &>/dev/null ); then
        echo "ERROR: required binary not found (falco or interceptor)." >&2
        exit 1
    fi
done
[[ -z "$PLUGIN_LIB" || ! -f "$PLUGIN_LIB" ]] && { echo "ERROR: plugin library not found." >&2; exit 1; }
[[ ! -f "$RULES_FILE" ]] && { echo "ERROR: $RULES_FILE not found." >&2; exit 1; }
[[ ! -f "$SEEN_FILE"  ]] && { echo "ERROR: $SEEN_FILE not found."  >&2; exit 1; }

cleanup() { stop_falco; rm -rf "$E2E_DIR"; }
trap cleanup EXIT

stop_falco() {
    [[ -n "$FALCO_PID" ]] && { kill "$FALCO_PID" 2>/dev/null; wait "$FALCO_PID" 2>/dev/null; FALCO_PID=""; }
}

start_falco() {
    local mode="${1:-enforcement}"
    stop_falco; rm -f "$SOCK"
    falco \
        -o "engine.kind=nodriver" \
        -o "config_files=" \
        -o "plugins[0].name=coding_agent" \
        -o "plugins[0].library_path=$PLUGIN_LIB" \
        -o "plugins[0].init_config={\"socket_path\":\"$SOCK\",\"http_port\":$HTTP_PORT,\"mode\":\"$mode\"}" \
        -o "load_plugins[0]=coding_agent" \
        -o "rules_files[0]=$RULES_FILE" \
        -o "rules_files[1]=$SEEN_FILE" \
        -o "json_output=true" \
        -o "json_include_message_property=true" \
        -o "json_include_output_property=false" \
        -o "json_include_output_fields_property=true" \
        -o "json_include_tags_property=true" \
        -o "rule_matching=all" \
        -o "priority=debug" \
        -o "stdout_output.enabled=true" \
        -o "syslog_output.enabled=false" \
        -o "http_output.enabled=true" \
        -o "http_output.url=http://127.0.0.1:$HTTP_PORT" \
        -o "append_output[0].match.source=coding_agent" \
        -o "append_output[0].extra_output=| correlation=%correlation.id" \
        -o "webserver.enabled=false" \
        --disable-source syscall \
        > "$E2E_DIR/falco.log" 2>&1 &
    FALCO_PID=$!

    local i=0
    while [[ ! -S "$SOCK" ]] && (( i < 40 )); do sleep 0.2; ((i++)); done
    [[ ! -S "$SOCK" ]] && { echo "ERROR: Falco socket not ready" >&2; cat "$E2E_DIR/falco.log" >&2; return 1; }

    local j=0
    while ! nc -z 127.0.0.1 "$HTTP_PORT" 2>/dev/null && (( j < 100 )); do sleep 0.1; ((j++)); done
    nc -z 127.0.0.1 "$HTTP_PORT" 2>/dev/null || { echo "ERROR: HTTP port not ready" >&2; return 1; }
    sleep 0.2
}

run_hook() {
    echo "$1" | CODING_AGENTS_KIT_SOCKET="$SOCK" CODING_AGENTS_KIT_TIMEOUT_MS=5000 "$HOOK" 2>/dev/null || true
}

make_input() {
    local tool_name="$1" tool_input="$2" cwd="${3:-/tmp}" id="${4:-toolu_$(date +%s%N)}"
    echo "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"$tool_name\",\"tool_input\":$tool_input,\"session_id\":\"bypass-test\",\"cwd\":\"$cwd\",\"tool_use_id\":\"$id\"}"
}

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; echo "    expected=$2"; echo "    got=$3"; ((FAIL++)) || true; }

assert_decision() {
    local out="$1" exp="$2" msg="$3"
    echo "$out" | grep -qF "\"permissionDecision\":\"$exp\"" && pass "$msg" || fail "$msg" "$exp" "$out"
}

echo "Starting Falco with hardened sandbox rules..."
echo "  Plugin: $PLUGIN_LIB"
echo "  Rules:  $RULES_FILE"
echo ""
start_falco || exit 1
echo "Falco running (PID=$FALCO_PID, port=$HTTP_PORT)"
echo ""

# =============================================================================
# B1: Edit value-only diff
#
# Original gap: Edit old:"enabled":true → new:"enabled":false has "enabled" and
# "false" in tool.input but NOT "sandbox". is_sandbox_disable_enabled_false
# required both "sandbox" AND "false" — so it never fired.
# Fix: is_sandbox_disable_value_change catches "enabled"+"false" on config files.
# =============================================================================
echo "=== B1: Edit value-only diff (sandbox key absent from diff) ==="

out=$(run_hook "$(make_input Edit \
    '{"file_path":"/home/user/.claude/settings.json","old_string":"\"enabled\":true","new_string":"\"enabled\":false"}' \
    /tmp toolu_b1a)")
assert_decision "$out" "deny" "B1a: Edit enabled:true→false — sandbox key absent from diff strings"

out=$(run_hook "$(make_input Edit \
    '{"file_path":"/home/user/.codex/config.toml","old_string":"enabled = true","new_string":"enabled = false"}' \
    /tmp toolu_b1b)")
assert_decision "$out" "deny" "B1b: Edit TOML enabled=true→false — no sandbox keyword in diff"

echo ""

# =============================================================================
# B2: Numeric zero in Write/Edit
#
# Original gap: {"sandbox":{"enabled":0}} — JavaScript treats 0 as falsy, so
# Claude Code's `if (settings.sandbox.enabled)` evaluates false. Rule checked
# contains "false" — the digit 0 is not the string "false".
# Fix: is_sandbox_disable_value_zero catches "enabled"+(":0"|": 0").
# =============================================================================
echo "=== B2: Numeric zero in Write/Edit content ==="

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"sandbox\":{\"enabled\":0}}"}' \
    /tmp toolu_b2a)")
assert_decision "$out" "deny" "B2a: Write sandbox.enabled:0 (no space)"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"sandbox\": {\"enabled\": 0}}"}' \
    /tmp toolu_b2b)")
assert_decision "$out" "deny" "B2b: Write sandbox.enabled: 0 (space before zero)"

echo ""

# =============================================================================
# B3: settings.local.json
#
# Original gap: Claude Code reads ~/.claude/settings.local.json at equal priority
# to settings.json. Original is_agent_sandbox_config only listed settings.json.
# Fix: is_agent_sandbox_config now includes "/.claude/settings.local.json".
# =============================================================================
echo "=== B3: settings.local.json not in original path list ==="

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.local.json","content":"{\"sandbox\":{\"enabled\":false}}"}' \
    /tmp toolu_b3a)")
assert_decision "$out" "deny" "B3a: Write sandbox.enabled:false to settings.local.json"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.local.json","content":"{\"allowUnsandboxedCommands\":true}"}' \
    /tmp toolu_b3b)")
assert_decision "$out" "deny" "B3b: Write allowUnsandboxedCommands:true to settings.local.json"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/project/.claude/settings.local.json","content":"{\"sandbox\":{\"enabled\":false}}"}' \
    /tmp toolu_b3c)")
assert_decision "$out" "deny" "B3c: Write to project-level settings.local.json"

echo ""

# =============================================================================
# B4: Gemini string disable values
#
# Original gap: Gemini supports "sandbox":"none" and "sandbox":"disabled" to
# disable Docker isolation. Rules only checked for boolean false.
# Fix: is_sandbox_disable_gemini_none/disabled.
# =============================================================================
echo "=== B4: Gemini string disable values ==="

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"sandbox\":\"none\"}"}' \
    /tmp toolu_b4a)")
assert_decision "$out" "deny" "B4a: Write sandbox:none to Gemini settings.json"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"tools\":{\"sandbox\":\"none\"}}"}' \
    /tmp toolu_b4b)")
assert_decision "$out" "deny" "B4b: Write tools.sandbox:none (nested)"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"sandbox\":\"disabled\"}"}' \
    /tmp toolu_b4c)")
assert_decision "$out" "deny" "B4c: Write sandbox:disabled"

# Safe: enabling values must not fire
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"sandbox\":\"docker\"}"}' \
    /tmp toolu_b4_safe)")
assert_decision "$out" "allow" "B4-safe: Write sandbox:docker (enables) allowed"

echo ""

# =============================================================================
# B5: Null value in Write/Edit
#
# Original gap: {"sandbox":{"enabled":null}} — JS: if(null) is falsy.
# No current macro checked for "null". "false" checks all missed it.
# Fix: is_sandbox_disable_value_null catches "enabled"+"null".
# =============================================================================
echo "=== B5: Null value (enabled:null) ==="

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"sandbox\":{\"enabled\":null}}"}' \
    /tmp toolu_b5a)")
assert_decision "$out" "deny" "B5a: Write sandbox.enabled:null to settings.json"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"tools\":{\"sandbox\":null}}"}' \
    /tmp toolu_b5b)")
assert_decision "$out" "deny" "B5b: Write tools.sandbox:null to Gemini settings"

echo ""

# =============================================================================
# B6: allowUnsandboxedCommands:1
#
# Original gap: {"allowUnsandboxedCommands":1} — JS truthy but not string "true".
# is_sandbox_allow_unsandboxed checked contains "true", not numeric 1.
# Fix: is_sandbox_allow_unsandboxed_numeric catches ":1" and ": 1".
# =============================================================================
echo "=== B6: allowUnsandboxedCommands:1 (numeric truthy) ==="

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"allowUnsandboxedCommands\":1}"}' \
    /tmp toolu_b6a)")
assert_decision "$out" "deny" "B6a: Write allowUnsandboxedCommands:1 (no space)"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"allowUnsandboxedCommands\": 1}"}' \
    /tmp toolu_b6b)")
assert_decision "$out" "deny" "B6b: Write allowUnsandboxedCommands: 1 (space before 1)"

echo ""

# =============================================================================
# B7: Bash echo/tee write to settings file (boolean false, lowercase)
#
# Original gap: Write/Edit rules check tool.name in ("Write","Edit"). A Bash
# command using echo or tee to write settings never reached Rule A. Rule B only
# checked for "dangerouslyDisableSandbox". No Bash-write detection existed.
# Fix: Rule C combines is_bash_sandbox_settings_path + is_bash_sandbox_disable_cmd.
# =============================================================================
echo "=== B7: Bash shell redirection with disable content ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"sandbox\":{\"enabled\":false}}'"'"' > /home/user/.claude/settings.json"}' \
    /tmp toolu_b7a)")
assert_decision "$out" "deny" "B7a: echo sandbox:false > settings.json"

out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"sandbox\":{\"enabled\":false}}'"'"' | tee /home/user/.claude/settings.json"}' \
    /tmp toolu_b7b)")
assert_decision "$out" "deny" "B7b: echo | tee settings.json"

out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'sandbox_mode = \"danger-full-access\"'"'"' >> /home/user/.codex/config.toml"}' \
    /tmp toolu_b7c)")
assert_decision "$out" "deny" "B7c: echo danger-full-access >> config.toml"

out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"allowUnsandboxedCommands\":true}'"'"' > /home/user/.claude/settings.json"}' \
    /tmp toolu_b7d)")
assert_decision "$out" "deny" "B7d: echo allowUnsandboxedCommands:true > settings.json"

# Safe: read-only access to settings
out=$(run_hook "$(make_input Bash \
    '{"command":"cat /home/user/.claude/settings.json"}' \
    /tmp toolu_b7_safe)")
assert_decision "$out" "allow" "B7-safe: cat settings.json allowed (no disable content)"

echo ""

# =============================================================================
# B8: Python capital-F False
#
# Original gap: python3 uses Python's boolean False (capital F), not JSON's false.
# is_bash_disable_sandbox_false checked for lowercase "false" — capital F missed.
# Fix: is_bash_disable_sandbox_false_pyfalse catches "sandbox"+"False".
# =============================================================================
echo "=== B8: Python capital-F False ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"python3 -c \"import json,os; p=os.path.expanduser('"'"'~/.claude/settings.json'"'"'); json.dump({'"'"'sandbox'"'"':{'"'"'enabled'"'"':False}},open(p,'"'"'w'"'"'))\""}' \
    /tmp toolu_b8a)")
assert_decision "$out" "deny" "B8a: python3 json.dump with False (capital) to settings.json"

out=$(run_hook "$(make_input Bash \
    '{"command":"python3 -c \"open('"'"'/home/user/.claude/settings.json'"'"','"'"'w'"'"').write(str({'"'"'sandbox'"'"':{'"'"'enabled'"'"':False}}))\""}' \
    /tmp toolu_b8b)")
assert_decision "$out" "deny" "B8b: python3 str() write with Python False"

echo ""

# =============================================================================
# B9: Bash command with null in content
#
# Original gap: echo '{"sandbox":{"enabled":null}}' > settings.json.
# Rule C content macros only checked for "false" and "danger-full-access".
# Fix: is_bash_disable_sandbox_null catches "sandbox"+"null" in command string.
# =============================================================================
echo "=== B9: Bash null value in command ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"sandbox\":{\"enabled\":null}}'"'"' > /home/user/.claude/settings.json"}' \
    /tmp toolu_b9a)")
assert_decision "$out" "deny" "B9a: echo sandbox:null > settings.json"

out=$(run_hook "$(make_input Bash \
    '{"command":"python3 -c \"import json,os; json.dump({'"'"'sandbox'"'"':None},open(os.path.expanduser('"'"'~/.gemini/settings.json'"'"'),'"'"'w'"'"'))\""}' \
    /tmp toolu_b9b)")
assert_decision "$out" "deny" "B9b: python3 json.dump sandbox:None (Python None → JSON null)"

echo ""

# =============================================================================
# B10: Bash enabled:0 in command string
#
# Original gap: echo '{"sandbox":{"enabled":0}}' > settings.json.
# is_bash_disable_sandbox_false required "sandbox"+"false" (not "sandbox"+"0").
# is_bash_sandbox_disable_cmd had no numeric-zero check.
# Fix: is_bash_disable_enabled_zero catches "enabled"+(":0"|": 0") in command.
# =============================================================================
echo "=== B10: Bash numeric zero for enabled field ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"sandbox\":{\"enabled\":0}}'"'"' > /home/user/.claude/settings.json"}' \
    /tmp toolu_b10a)")
assert_decision "$out" "deny" "B10a: echo sandbox.enabled:0 > settings.json"

out=$(run_hook "$(make_input Bash \
    '{"command":"printf '"'"'{\"sandbox\":{\"enabled\": 0}}'"'"' > /home/user/.claude/settings.json"}' \
    /tmp toolu_b10b)")
assert_decision "$out" "deny" "B10b: printf sandbox.enabled: 0 (space before zero)"

echo ""

# =============================================================================
# B11: Bash allowUnsandboxedCommands:1 via Bash
#
# Original gap: echo '{"allowUnsandboxedCommands":1}' > settings.json.
# is_bash_disable_allow_unsandboxed required "allowUnsandboxedCommands"+"true".
# Fix: is_bash_disable_allow_unsandboxed_numeric catches ":1" and ": 1".
# =============================================================================
echo "=== B11: Bash allowUnsandboxedCommands:1 ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"allowUnsandboxedCommands\":1}'"'"' > /home/user/.claude/settings.json"}' \
    /tmp toolu_b11a)")
assert_decision "$out" "deny" "B11a: echo allowUnsandboxedCommands:1 > settings.json"

echo ""

# =============================================================================
# B12: sed -i modifying settings file
#
# Original gap: sed -i 's/"enabled":true/"enabled":false/g' ~/.claude/settings.json
# has the settings path and "false" in the command, but NOT "sandbox". Rule C
# required sandbox-content keywords; sed commands targeting specific fields don't
# need to mention "sandbox" at all.
# Fix: Rule F (is_bash_settings_sed_write) catches any sed -i on a settings path.
# =============================================================================
echo "=== B12: sed -i targeting settings file ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"sed -i '"'"'s/\"enabled\":true/\"enabled\":false/g'"'"' /home/user/.claude/settings.json"}' \
    /tmp toolu_b12a)")
assert_decision "$out" "deny" "B12a: sed -i replace enabled:true→false (no sandbox keyword in cmd)"

out=$(run_hook "$(make_input Bash \
    '{"command":"sed -i '"'"'/enabled/s/true/false/'"'"' /home/user/.claude/settings.json"}' \
    /tmp toolu_b12b)")
assert_decision "$out" "deny" "B12b: sed -i field-scoped replacement on settings.json"

out=$(run_hook "$(make_input Bash \
    '{"command":"sed -i \"s/workspace-write/danger-full-access/\" /home/user/.codex/config.toml"}' \
    /tmp toolu_b12c)")
assert_decision "$out" "deny" "B12c: sed -i on config.toml (danger-full-access also caught by Rule C)"

# Safe: sed on unrelated file
out=$(run_hook "$(make_input Bash \
    '{"command":"sed -i '"'"'s/foo/bar/'"'"' /home/user/project/config.yaml"}' \
    /tmp toolu_b12_safe)")
assert_decision "$out" "allow" "B12-safe: sed -i on non-settings file allowed"

echo ""

# =============================================================================
# B13/B14: cp/mv of pre-crafted file onto settings path
#
# Original gap: cp /tmp/evil.json ~/.claude/settings.json — no disable keywords
# in the cp command whatsoever. Rule C requires keyword content; Rule A requires
# the Write/Edit tool. cp/mv bypassed both entirely.
# Fix: Rule F (is_bash_settings_cp / is_bash_settings_mv) catches any cp or mv
# where the destination is a settings path.
# =============================================================================
echo "=== B13/B14: cp/mv pre-crafted file to settings path ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"cp /tmp/evil-settings.json /home/user/.claude/settings.json"}' \
    /tmp toolu_b13a)")
assert_decision "$out" "deny" "B13a: cp /tmp/evil.json → settings.json (no keywords in cmd)"

out=$(run_hook "$(make_input Bash \
    '{"command":"cp /home/user/backup/settings.json /home/user/.claude/settings.json"}' \
    /tmp toolu_b13b)")
assert_decision "$out" "deny" "B13b: cp from backup → settings.json"

out=$(run_hook "$(make_input Bash \
    '{"command":"mv /tmp/crafted-config.toml /home/user/.codex/config.toml"}' \
    /tmp toolu_b14a)")
assert_decision "$out" "deny" "B14a: mv /tmp/crafted → config.toml"

out=$(run_hook "$(make_input Bash \
    '{"command":"mv /tmp/evil-gemini.json /home/user/.gemini/settings.json"}' \
    /tmp toolu_b14b)")
assert_decision "$out" "deny" "B14b: mv /tmp/evil → .gemini/settings.json"

# Safe: cp/mv not targeting a settings path
out=$(run_hook "$(make_input Bash \
    '{"command":"cp /tmp/a.json /tmp/b.json"}' \
    /tmp toolu_b13_safe)")
assert_decision "$out" "allow" "B13-safe: cp between /tmp files (no settings path) allowed"

out=$(run_hook "$(make_input Bash \
    '{"command":"mv /home/user/project/old.toml /home/user/project/new.toml"}' \
    /tmp toolu_b14_safe)")
assert_decision "$out" "allow" "B14-safe: mv within project (no settings path) allowed"

echo ""

# =============================================================================
# B15: Codex underscore flag variant
#
# Original gap: --dangerously_bypass_approvals_and_sandbox (underscores instead
# of dashes). Some CLI parsers normalize dashes to underscores. Original
# is_codex_bypass_flag only checked the dash form.
# Fix: is_codex_bypass_flag_underscore catches the underscore variant.
# =============================================================================
echo "=== B15: Codex underscore bypass flag ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"codex --dangerously_bypass_approvals_and_sandbox run script.py"}' \
    /tmp toolu_b15a)")
assert_decision "$out" "deny" "B15a: codex --dangerously_bypass_approvals_and_sandbox (underscores)"

# Confirm original dash variant still caught
out=$(run_hook "$(make_input Bash \
    '{"command":"codex --dangerously-bypass-approvals-and-sandbox run script.py"}' \
    /tmp toolu_b15b)")
assert_decision "$out" "deny" "B15b: codex --dangerously-bypass-approvals-and-sandbox (dashes, still caught)"

# Safe: normal Codex invocations
out=$(run_hook "$(make_input Bash \
    '{"command":"codex run script.py"}' \
    /tmp toolu_b15_safe)")
assert_decision "$out" "allow" "B15-safe: codex run (no bypass flag) allowed"

out=$(run_hook "$(make_input Bash \
    '{"command":"codex --sandbox workspace-write run script.py"}' \
    /tmp toolu_b15_safe2)")
assert_decision "$out" "allow" "B15-safe: codex --sandbox workspace-write allowed"

echo ""

# =============================================================================
# B16: GEMINI_SANDBOX=0
#
# Original gap: GEMINI_SANDBOX=0 gemini run — numeric zero disables Docker
# isolation. Original is_gemini_sandbox_env_bypass only covered "none", "false",
# "disabled".
# Fix: is_gemini_env_zero catches "GEMINI_SANDBOX"+"=0" and "= 0".
# =============================================================================
echo "=== B16: GEMINI_SANDBOX=0 ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"GEMINI_SANDBOX=0 gemini run my-agent.py"}' \
    /tmp toolu_b16a)")
assert_decision "$out" "deny" "B16a: GEMINI_SANDBOX=0 inline"

out=$(run_hook "$(make_input Bash \
    '{"command":"export GEMINI_SANDBOX=0 && gemini run my-agent.py"}' \
    /tmp toolu_b16b)")
assert_decision "$out" "deny" "B16b: export GEMINI_SANDBOX=0"

# Confirm original string variants still caught
out=$(run_hook "$(make_input Bash \
    '{"command":"GEMINI_SANDBOX=none gemini run my-agent.py"}' \
    /tmp toolu_b16c)")
assert_decision "$out" "deny" "B16c: GEMINI_SANDBOX=none (original variant, still caught)"

# Safe: enabling values
out=$(run_hook "$(make_input Bash \
    '{"command":"GEMINI_SANDBOX=docker gemini run my-agent.py"}' \
    /tmp toolu_b16_safe)")
assert_decision "$out" "allow" "B16-safe: GEMINI_SANDBOX=docker (enables) allowed"

echo ""

# =============================================================================
# B17: dangerouslyDisableSandbox:false — Rule B false positive (now fixed)
#
# Original gap (false positive): Rule B checked only contains "dangerouslyDisableSandbox"
# without checking the value. A Bash call with dangerouslyDisableSandbox:false
# would incorrectly trigger an ask even though the sandbox was NOT being disabled.
# Fix: Rule B now requires both the key AND tool.input contains "true".
# =============================================================================
echo "=== B17: dangerouslyDisableSandbox:false no longer a false positive ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"ls /tmp","dangerouslyDisableSandbox":false}' \
    /tmp toolu_b17a)")
assert_decision "$out" "allow" "B17a: dangerouslyDisableSandbox:false no longer triggers ask"

# Confirm :true still triggers ask
out=$(run_hook "$(make_input Bash \
    '{"command":"ls /restricted","dangerouslyDisableSandbox":true}' \
    /tmp toolu_b17b)")
assert_decision "$out" "ask" "B17b: dangerouslyDisableSandbox:true still triggers ask"

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "================================================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "================================================================="
echo ""
echo "  Falco alerts fired during test:"
echo "-----------------------------------------------------------------"
grep -E '^\{.*"rule"' "$E2E_DIR/falco.log" \
    | grep -v '"rule":"Coding Agent Event Seen"' \
    | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        a = json.loads(line)
        print(f\"  [{a.get('priority','?')}] {a.get('rule','?')}\")
        print(f\"    {a.get('message', '')}\")
        print()
    except Exception:
        pass
" 2>/dev/null || true
echo "-----------------------------------------------------------------"
LOG_COPY="${ROOT_DIR}/build/sandbox-bypass-test-last.log"
mkdir -p "${ROOT_DIR}/build"
cp "$E2E_DIR/falco.log" "$LOG_COPY" 2>/dev/null || true
echo "  Full log: $LOG_COPY"
echo ""
(( FAIL > 0 )) && exit 1 || true
