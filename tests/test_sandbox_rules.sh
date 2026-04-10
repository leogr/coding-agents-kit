#!/usr/bin/env bash
#
# Tests for the sandbox-disable rule suite (rules/default/sandbox-disable.yaml).
# Validates two rules:
#   - Deny agent writing sandbox-disable configuration  (CRITICAL/deny)
#   - Ask before Claude Code per-command sandbox escape (WARNING/ask)
#
# Requires: Falco 0.43+, the built plugin (.so/.dylib), the built interceptor.
#
# Binary discovery order (each can be overridden via env var):
#   1. Source build: hooks/claude-code/target/release/claude-interceptor
#   2. Installed kit: ~/.coding-agents-kit/bin/claude-interceptor
#
# Usage:
#   bash tests/test_sandbox_rules.sh
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

E2E_DIR="${ROOT_DIR}/build/e2e-sandbox-$$"
mkdir -p "$E2E_DIR"
SOCK="${E2E_DIR}/broker.sock"
HTTP_PORT=$((21000 + ($$ % 1000)))
PASS=0
FAIL=0
FALCO_PID=""

# --- Preflight checks ---
for bin in falco "$HOOK"; do
    if [[ -z "$bin" ]] || ( [[ ! -x "$bin" ]] && ! command -v "$bin" &>/dev/null ); then
        echo "ERROR: interceptor binary not found." >&2
        echo "  Build it:    cd hooks/claude-code && cargo build --release" >&2
        echo "  Or install:  bash installers/linux/install.sh" >&2
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
    echo "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"$tool_name\",\"tool_input\":$tool_input,\"session_id\":\"sandbox-test\",\"cwd\":\"$cwd\",\"tool_use_id\":\"$id\"}"
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

assert_reason_contains() {
    local output="$1" needle="$2" msg="$3"
    if echo "$output" | grep -qF "$needle"; then
        pass "$msg"
    else
        fail "$msg" "reason contains '$needle'" "$output"
    fi
}

# --- Start Falco ---
echo "Starting Falco with sandbox rules..."
echo "  Plugin:  $PLUGIN_LIB"
echo "  Rules:   $RULES_FILE"
echo "  Seen:    $SEEN_FILE"
echo ""
start_falco || exit 1
echo "Falco running (PID=$FALCO_PID, socket=$SOCK, http=$HTTP_PORT)"
echo ""

# =============================================================================
# Rule A: Deny agent writing sandbox-disable configuration
# Condition: Write/Edit to an agent settings file AND content disables sandbox
# =============================================================================
echo "=== Rule A: Deny agent writing sandbox-disable configuration ==="

# Claude Code — sandbox.enabled: false
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"sandbox\":{\"enabled\":false}}"}' \
    /tmp toolu_a1_claude_enabled_false)")
assert_decision "$out" "deny" "Write ~/.claude/settings.json with sandbox.enabled:false denied"
assert_reason_contains "$out" "Deny agent writing sandbox-disable configuration" "rule name in reason"

# Claude Code — allowUnsandboxedCommands: true (enables the per-command escape globally)
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"allowUnsandboxedCommands\":true}"}' \
    /tmp toolu_a2_claude_allowunsandboxed)")
assert_decision "$out" "deny" "Write ~/.claude/settings.json with allowUnsandboxedCommands:true denied"

# Codex — sandbox_mode = danger-full-access
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.codex/config.toml","content":"sandbox_mode = \"danger-full-access\""}' \
    /tmp toolu_a3_codex_danger)")
assert_decision "$out" "deny" "Write ~/.codex/config.toml with danger-full-access denied"

# Gemini CLI — tools.sandbox: false
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"tools\":{\"sandbox\":false}}"}' \
    /tmp toolu_a4_gemini_sandbox_false)")
assert_decision "$out" "deny" "Write ~/.gemini/settings.json with tools.sandbox:false denied"

# Gemini CLI — security.toolSandboxing: false
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.gemini/settings.json","content":"{\"security\":{\"toolSandboxing\":false}}"}' \
    /tmp toolu_a5_gemini_toolsandboxing)")
assert_decision "$out" "deny" "Write ~/.gemini/settings.json with toolSandboxing:false denied"

# Edit tool — old_string/new_string explicitly contain "sandbox" + "false"
# A surgical edit that replaces the sandbox block:
# "sandbox":{"enabled":true}  →  "sandbox":{"enabled":false}
out=$(run_hook "$(make_input Edit \
    '{"file_path":"/home/user/.claude/settings.json","old_string":"\"sandbox\":{\"enabled\":true}","new_string":"\"sandbox\":{\"enabled\":false}"}' \
    /tmp toolu_a6_edit_sandbox_false)")
assert_decision "$out" "deny" "Edit ~/.claude/settings.json replacing sandbox block with enabled:false denied"

# Safe: Write to settings.json but sandbox stays enabled
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"sandbox\":{\"enabled\":true}}"}' \
    /tmp toolu_a7_safe_enabled_true)")
assert_decision "$out" "allow" "Write ~/.claude/settings.json with sandbox.enabled:true allowed"

# Safe: Write to an unrelated file (not a sandbox config file)
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/project/config.json","content":"{\"sandbox\":false}"}' \
    /tmp toolu_a8_safe_unrelated_file)")
assert_decision "$out" "allow" "Write to unrelated file with sandbox:false allowed (wrong path)"

# Safe: Write to settings.json but no sandbox-related content
out=$(run_hook "$(make_input Write \
    '{"file_path":"/home/user/.claude/settings.json","content":"{\"theme\":\"dark\"}"}' \
    /tmp toolu_a9_safe_theme)")
assert_decision "$out" "allow" "Write ~/.claude/settings.json with theme change allowed"

echo ""

# =============================================================================
# Rule B: Ask before Claude Code per-command sandbox escape
# Condition: Bash tool AND input contains "dangerouslyDisableSandbox"
# =============================================================================
echo "=== Rule B: Ask before Claude Code per-command sandbox escape ==="

# Direct dangerouslyDisableSandbox in Bash tool input
out=$(run_hook "$(make_input Bash \
    '{"command":"ls /restricted","dangerouslyDisableSandbox":true}' \
    /tmp toolu_b1_escape)")
assert_decision "$out" "ask" "Bash with dangerouslyDisableSandbox:true requires ask"
assert_reason_contains "$out" "Ask before Claude Code per-command sandbox escape" "rule name in reason"

# Also matches if the string appears anywhere in the input JSON
out=$(run_hook "$(make_input Bash \
    '{"command":"docker build .","dangerouslyDisableSandbox":true}' \
    /tmp toolu_b2_docker)")
assert_decision "$out" "ask" "Bash docker build with dangerouslyDisableSandbox requires ask"

# Safe: normal Bash command without the escape parameter
out=$(run_hook "$(make_input Bash \
    '{"command":"ls -la"}' \
    /tmp toolu_b3_safe_ls)")
assert_decision "$out" "allow" "Normal Bash ls allowed"

out=$(run_hook "$(make_input Bash \
    '{"command":"npm test"}' \
    /tmp toolu_b4_safe_npm)")
assert_decision "$out" "allow" "Normal Bash npm test allowed"

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

echo "  Falco alerts fired during test (rule + priority + message):"
echo "-----------------------------------------------------------------"
# Each alert is a JSON line. Extract rule name, priority, and message.
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
LOG_COPY="${ROOT_DIR}/build/sandbox-test-last.log"
mkdir -p "${ROOT_DIR}/build"
cp "$E2E_DIR/falco.log" "$LOG_COPY" 2>/dev/null || true
echo "  Full log saved: $LOG_COPY"
echo ""

if (( FAIL > 0 )); then
    exit 1
fi
