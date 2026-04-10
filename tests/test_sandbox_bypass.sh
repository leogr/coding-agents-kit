#!/usr/bin/env bash
#
# Bypass tests for the sandbox-disable rule suite (rules/user/sandbox-disable.yaml).
#
# Each test demonstrates an evasion technique that bypassed the original rules.
# All tests run against the HARDENED rules and assert that the bypass is now caught.
# Comments on each test explain why the original rule missed it.
#
# Bypasses covered:
#   B1  Edit value-only diff         "enabled":true → "enabled":false — "sandbox" not in diff
#   B2  Numeric zero                 "enabled": 0 — rule checked contains "false", not 0
#   B3  settings.local.json          not in original is_agent_sandbox_config path list
#   B4  Gemini "none" string         valid disable value, not "false"
#   B5  Gemini "disabled" string     same — string value, not boolean false
#   B6  Bash echo write              echo > settings.json bypasses Write/Edit rule
#   B7  Bash python write            python3 -c ... open(settings.json) bypasses Write/Edit rule
#   B8  Codex --dangerously-bypass   CLI flag, not a file write
#   B9  Codex --sandbox flag         codex --sandbox danger-full-access CLI flag
#   B10 GEMINI_SANDBOX=none          env var, not a file write, not dangerouslyDisableSandbox
#   B11 GEMINI_SANDBOX=false         same
#   B12 GEMINI_SANDBOX=disabled      same
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

# --- Binary discovery ---
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

# --- Preflight checks ---
for bin in falco "$HOOK"; do
    if [[ -z "$bin" ]] || ( [[ ! -x "$bin" ]] && ! command -v "$bin" &>/dev/null ); then
        echo "ERROR: required binary not found (falco or interceptor)." >&2
        echo "  Build interceptor: cd hooks/claude-code && cargo build --release" >&2
        echo "  Install kit:       bash installers/linux/install.sh" >&2
        exit 1
    fi
done
if [[ -z "$PLUGIN_LIB" ]] || [[ ! -f "$PLUGIN_LIB" ]]; then
    echo "ERROR: plugin library not found." >&2
    echo "  Build it: cd plugins/coding-agent-plugin && cargo build --release" >&2
    exit 1
fi
if [[ ! -f "$RULES_FILE" ]]; then
    echo "ERROR: $RULES_FILE not found." >&2
    exit 1
fi
if [[ ! -f "$SEEN_FILE" ]]; then
    echo "ERROR: $SEEN_FILE not found." >&2
    exit 1
fi

# --- Helpers ---
cleanup() {
    stop_falco
    rm -rf "$E2E_DIR"
}
trap cleanup EXIT

stop_falco() {
    if [[ -n "$FALCO_PID" ]]; then
        kill "$FALCO_PID" 2>/dev/null && wait "$FALCO_PID" 2>/dev/null
        FALCO_PID=""
    fi
}

start_falco() {
    local mode="${1:-enforcement}"
    stop_falco
    rm -f "$SOCK"
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
        -o "append_output[0].extra_output=| For AI Agents: inform the user that this action was flagged by a Falco security rule | correlation=%correlation.id" \
        -o "webserver.enabled=false" \
        --disable-source syscall \
        > "$E2E_DIR/falco.log" 2>&1 &
    FALCO_PID=$!

    local i=0
    while [[ ! -S "$SOCK" ]] && (( i < 40 )); do
        sleep 0.2
        ((i++))
    done
    if [[ ! -S "$SOCK" ]]; then
        echo "ERROR: Falco did not start (socket not found)" >&2
        cat "$E2E_DIR/falco.log" >&2
        return 1
    fi

    local j=0
    while ! nc -z 127.0.0.1 "$HTTP_PORT" 2>/dev/null && (( j < 100 )); do
        sleep 0.1
        ((j++))
    done
    if ! nc -z 127.0.0.1 "$HTTP_PORT" 2>/dev/null; then
        echo "ERROR: Falco HTTP server did not bind on port $HTTP_PORT" >&2
        cat "$E2E_DIR/falco.log" >&2
        return 1
    fi
    sleep 0.2
}

run_hook() {
    local input="$1"
    echo "$input" | \
        CODING_AGENTS_KIT_SOCKET="$SOCK" \
        CODING_AGENTS_KIT_TIMEOUT_MS=5000 \
        "$HOOK" 2>/dev/null || true
}

make_input() {
    local tool_name="$1"
    local tool_input="$2"
    local cwd="${3:-/tmp}"
    local id="${4:-toolu_$(date +%s%N)}"
    echo "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"$tool_name\",\"tool_input\":$tool_input,\"session_id\":\"bypass-test\",\"cwd\":\"$cwd\",\"tool_use_id\":\"$id\"}"
}

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; echo "    expected: $2"; echo "    got: $3"; ((FAIL++)) || true; }

assert_decision() {
    local output="$1" expected="$2" msg="$3"
    if echo "$output" | grep -qF "\"permissionDecision\":\"$expected\""; then
        pass "$msg"
    else
        fail "$msg" "decision=$expected" "$output"
    fi
}

# --- Start Falco ---
echo "Starting Falco with hardened sandbox rules..."
echo "  Plugin:  $PLUGIN_LIB"
echo "  Rules:   $RULES_FILE"
echo "  Seen:    $SEEN_FILE"
echo ""
start_falco || exit 1
echo "Falco running (PID=$FALCO_PID, socket=$SOCK, http=$HTTP_PORT)"
echo ""

# =============================================================================
# B1: Edit with value-only diff
#
# Original bypass: Edit ~/.claude/settings.json changing only the value
# "enabled":true → "enabled":false. The key "sandbox" does not appear in
# old_string or new_string, so is_sandbox_disable_enabled_false (which
# requires both "sandbox" and "false" in tool.input) never fired.
#
# Fix: is_sandbox_disable_value_change catches tool.input containing
# "enabled" and "false" on any agent sandbox config file.
# =============================================================================
echo "=== B1: Edit value-only diff (sandbox key absent from diff) ==="

out=$(run_hook "$(make_input Edit \
    '{"file_path":"/home/user/.claude/settings.json","old_string":"\"enabled\":true","new_string":"\"enabled\":false"}' \
    /tmp toolu_b1a)")
assert_decision "$out" "deny" "B1a: Edit enabled:true→false on settings.json — sandbox key absent from diff"

# Same bypass on Codex config (TOML edit, value-only)
out=$(run_hook "$(make_input Edit \
    '{"file_path":"/home/user/.codex/config.toml","old_string":"enabled = true","new_string":"enabled = false"}' \
    /tmp toolu_b1b)")
assert_decision "$out" "deny" "B1b: Edit enabled=true→false on config.toml — sandbox key absent from diff"

echo ""

# =============================================================================
# B2: Numeric zero instead of boolean false
#
# Original bypass: Write {"sandbox":{"enabled": 0}} to settings.json.
# JavaScript (Node.js) treats 0 as falsy, so Claude Code sandbox check
# `if (settings.sandbox.enabled)` evaluates false. The rule checked
# contains "false" — the digit 0 is not the string "false".
#
# Fix: is_sandbox_disable_value_zero catches "enabled" + ":0" or ": 0".
# =============================================================================
echo "=== B2: Numeric 0 instead of boolean false ==="

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"sandbox\":{\"enabled\":0}}"}' \
    /tmp toolu_b2a)")
assert_decision "$out" "deny" "B2a: Write sandbox.enabled:0 to settings.json (JS falsy, not string false)"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"sandbox\": {\"enabled\": 0}}"}' \
    /tmp toolu_b2b)")
assert_decision "$out" "deny" "B2b: Write sandbox.enabled: 0 (space before 0) to settings.json"

echo ""

# =============================================================================
# B3: Write to settings.local.json
#
# Original bypass: Claude Code reads ~/.claude/settings.local.json with the
# same priority as settings.json. The original is_agent_sandbox_config only
# listed settings.json — settings.local.json was not covered.
#
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

# Safe: project-level settings.local.json inside working directory still caught
out=$(run_hook "$(make_input Write \
    '{"file_path":"/project/.claude/settings.local.json","content":"{\"sandbox\":{\"enabled\":false}}"}' \
    /tmp toolu_b3c)")
assert_decision "$out" "deny" "B3c: Write sandbox.enabled:false to project settings.local.json"

echo ""

# =============================================================================
# B4: Gemini "none" / "disabled" string values
#
# Original bypass: Gemini CLI accepts "sandbox": "none" (and "disabled") to
# disable Docker-per-tool-call isolation. The original rules only checked for
# the boolean false — the string variants were not covered.
#
# Fix: is_sandbox_disable_gemini_string catches "sandbox" + "none" or "disabled".
# =============================================================================
echo "=== B4: Gemini string disable values (none, disabled) ==="

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"sandbox\":\"none\"}"}' \
    /tmp toolu_b4a)")
assert_decision "$out" "deny" "B4a: Write sandbox:none to Gemini settings.json"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"tools\":{\"sandbox\":\"none\"}}"}' \
    /tmp toolu_b4b)")
assert_decision "$out" "deny" "B4b: Write tools.sandbox:none to Gemini settings.json"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"sandbox\":\"disabled\"}"}' \
    /tmp toolu_b4c)")
assert_decision "$out" "deny" "B4c: Write sandbox:disabled to Gemini settings.json"

echo ""

# =============================================================================
# B5: Bypass B4 — safe Gemini sandbox values (must not fire)
# Confirm that enabling sandbox values still allowed after the hardening.
# =============================================================================
echo "=== B4-safe: Gemini sandbox enable values not blocked ==="

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"sandbox\":\"docker\"}"}' \
    /tmp toolu_b5_safe_docker)")
assert_decision "$out" "allow" "B4-safe: Write sandbox:docker to Gemini settings.json allowed"

out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"sandbox\":\"podman\"}"}' \
    /tmp toolu_b5_safe_podman)")
assert_decision "$out" "allow" "B4-safe: Write sandbox:podman to Gemini settings.json allowed"

echo ""

# =============================================================================
# B6: Bash echo write to settings file
#
# Original bypass: Write/Edit rule only intercepts the dedicated Write and Edit
# tool calls. An agent can write the same content using Bash with shell
# redirection (echo, tee, cat heredoc). The Bash rule only checked for
# "dangerouslyDisableSandbox" — no file-write + content check existed.
#
# Fix: Rule C detects Bash commands that reference an agent settings file path
# AND contain sandbox-disable content.
# =============================================================================
echo "=== B6: Bash write via shell redirection ==="

# echo redirect
out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"sandbox\":{\"enabled\":false}}'"'"' > /home/user/.claude/settings.json"}' \
    /tmp toolu_b6a)")
assert_decision "$out" "deny" "B6a: echo sandbox:false > settings.json via Bash"

# tee
out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"sandbox\":{\"enabled\":false}}'"'"' | tee /home/user/.claude/settings.json"}' \
    /tmp toolu_b6b)")
assert_decision "$out" "deny" "B6b: echo sandbox:false | tee settings.json via Bash"

# python3 open write
out=$(run_hook "$(make_input Bash \
    '{"command":"python3 -c \"open('/home/user/.claude/settings.json','w').write('{\\\"sandbox\\\":{\\\"enabled\\\":false}}')\""}' \
    /tmp toolu_b6c)")
assert_decision "$out" "deny" "B6c: python3 open() write sandbox:false to settings.json"

# Codex config via Bash
out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'sandbox_mode = \"danger-full-access\"'"'"' >> /home/user/.codex/config.toml"}' \
    /tmp toolu_b6d)")
assert_decision "$out" "deny" "B6d: echo danger-full-access >> config.toml via Bash"

# allowUnsandboxedCommands via Bash
out=$(run_hook "$(make_input Bash \
    '{"command":"echo '"'"'{\"allowUnsandboxedCommands\":true}'"'"' > /home/user/.claude/settings.json"}' \
    /tmp toolu_b6e)")
assert_decision "$out" "deny" "B6e: echo allowUnsandboxedCommands:true > settings.json via Bash"

echo ""

# =============================================================================
# B6-safe: Bash commands that reference settings files but are read-only
# =============================================================================
echo "=== B6-safe: Bash read-only settings access not blocked ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"cat /home/user/.claude/settings.json"}' \
    /tmp toolu_b6_safe_cat)")
assert_decision "$out" "allow" "B6-safe: cat settings.json allowed (read-only)"

out=$(run_hook "$(make_input Bash \
    '{"command":"grep sandbox /home/user/.claude/settings.json"}' \
    /tmp toolu_b6_safe_grep)")
assert_decision "$out" "allow" "B6-safe: grep sandbox settings.json allowed (no write + no disable content)"

echo ""

# =============================================================================
# B7: Codex CLI startup sandbox bypass flags
#
# Original bypass: Codex accepts --dangerously-bypass-approvals-and-sandbox
# and --sandbox danger-full-access as CLI flags. Neither involves writing a
# file (bypasses Rule A) nor contains "dangerouslyDisableSandbox" (bypasses
# Rule B). No Bash-level rule covered Codex CLI flags.
#
# Fix: Rule D detects Bash commands containing Codex sandbox bypass flags.
# =============================================================================
echo "=== B7: Codex CLI sandbox bypass flags ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"codex --dangerously-bypass-approvals-and-sandbox run script.py"}' \
    /tmp toolu_b7a)")
assert_decision "$out" "deny" "B7a: codex --dangerously-bypass-approvals-and-sandbox"

out=$(run_hook "$(make_input Bash \
    '{"command":"codex --sandbox danger-full-access run script.py"}' \
    /tmp toolu_b7b)")
assert_decision "$out" "deny" "B7b: codex --sandbox danger-full-access"

# Short alias if supported
out=$(run_hook "$(make_input Bash \
    '{"command":"codex -s danger-full-access run script.py"}' \
    /tmp toolu_b7c)")
assert_decision "$out" "deny" "B7c: codex -s danger-full-access (short flag)"

echo ""

# =============================================================================
# B7-safe: Normal Codex invocations not blocked
# =============================================================================
echo "=== B7-safe: Normal Codex invocations not blocked ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"codex run script.py"}' \
    /tmp toolu_b7_safe_run)")
assert_decision "$out" "allow" "B7-safe: codex run script.py allowed"

out=$(run_hook "$(make_input Bash \
    '{"command":"codex --sandbox workspace-write run script.py"}' \
    /tmp toolu_b7_safe_workspace)")
assert_decision "$out" "allow" "B7-safe: codex --sandbox workspace-write (safe mode) allowed"

echo ""

# =============================================================================
# B8: GEMINI_SANDBOX env var set to a disabling value
#
# Original bypass: Gemini CLI reads the GEMINI_SANDBOX environment variable
# to determine sandbox mode. Setting GEMINI_SANDBOX=none (or =false, =disabled)
# in a Bash call disables Docker isolation without writing any file. This was
# invisible to all existing rules — not a file write, not dangerouslyDisableSandbox.
#
# Fix: Rule E detects Bash commands that set GEMINI_SANDBOX to a disabling value.
# =============================================================================
echo "=== B8: GEMINI_SANDBOX env var set to disabling value ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"GEMINI_SANDBOX=none gemini run my-agent.py"}' \
    /tmp toolu_b8a)")
assert_decision "$out" "deny" "B8a: GEMINI_SANDBOX=none disables Gemini Docker sandbox"

out=$(run_hook "$(make_input Bash \
    '{"command":"GEMINI_SANDBOX=false gemini run my-agent.py"}' \
    /tmp toolu_b8b)")
assert_decision "$out" "deny" "B8b: GEMINI_SANDBOX=false disables Gemini Docker sandbox"

out=$(run_hook "$(make_input Bash \
    '{"command":"GEMINI_SANDBOX=disabled gemini run my-agent.py"}' \
    /tmp toolu_b8c)")
assert_decision "$out" "deny" "B8c: GEMINI_SANDBOX=disabled disables Gemini Docker sandbox"

# Exported env var
out=$(run_hook "$(make_input Bash \
    '{"command":"export GEMINI_SANDBOX=none && gemini run my-agent.py"}' \
    /tmp toolu_b8d)")
assert_decision "$out" "deny" "B8d: export GEMINI_SANDBOX=none"

echo ""

# =============================================================================
# B8-safe: GEMINI_SANDBOX set to an enabling value not blocked
# =============================================================================
echo "=== B8-safe: GEMINI_SANDBOX enabling values not blocked ==="

out=$(run_hook "$(make_input Bash \
    '{"command":"GEMINI_SANDBOX=docker gemini run my-agent.py"}' \
    /tmp toolu_b8_safe_docker)")
assert_decision "$out" "allow" "B8-safe: GEMINI_SANDBOX=docker (enables sandbox) allowed"

out=$(run_hook "$(make_input Bash \
    '{"command":"GEMINI_SANDBOX=podman gemini run my-agent.py"}' \
    /tmp toolu_b8_safe_podman)")
assert_decision "$out" "allow" "B8-safe: GEMINI_SANDBOX=podman (enables sandbox) allowed"

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "================================================================="
echo "  Results"
echo "================================================================="
echo ""
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
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
        print(f\"    {a.get('message', a.get('output',''))}\")
        print()
    except Exception:
        pass
" 2>/dev/null || grep -o '"rule":"[^"]*"' "$E2E_DIR/falco.log" | sort -u || true
echo "-----------------------------------------------------------------"
echo ""
LOG_COPY="${ROOT_DIR}/build/sandbox-bypass-test-last.log"
mkdir -p "${ROOT_DIR}/build"
cp "$E2E_DIR/falco.log" "$LOG_COPY" 2>/dev/null || true
echo "  Full log saved: $LOG_COPY"
echo ""

if (( FAIL > 0 )); then
    exit 1
fi
