#!/usr/bin/env bash
#
# End-to-end tests for the coding-agents-kit pipeline.
# Requires: Falco 0.43+, the built plugin (.so), the built interceptor.
#
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." &>/dev/null && pwd)"
HOOK="${ROOT_DIR}/hooks/claude-code/target/release/claude-interceptor"
case "$(uname -s)" in
    Darwin) PLUGIN_EXT="dylib" ;;
    *)      PLUGIN_EXT="so" ;;
esac
PLUGIN_LIB="${ROOT_DIR}/plugins/coding-agent-plugin/target/release/libcoding_agent_plugin.${PLUGIN_EXT}"
# Use build/ for temp files to avoid /tmp restrictions on some platforms.
E2E_DIR="${ROOT_DIR}/build/e2e-$$"
mkdir -p "$E2E_DIR"
SOCK="${E2E_DIR}/broker.sock"
HTTP_PORT=$((19000 + ($$ % 1000)))
PASS=0
FAIL=0
FALCO_PID=""

# --- Preflight checks ---
for bin in falco "$HOOK"; do
    if [[ ! -x "$bin" ]] && ! command -v "$bin" &>/dev/null; then
        echo "ERROR: $bin not found" >&2
        exit 1
    fi
done
if [[ ! -f "$PLUGIN_LIB" ]]; then
    echo "ERROR: plugin not found at $PLUGIN_LIB (run 'cargo build --release' in plugins/coding-agent-plugin/)" >&2
    exit 1
fi

# --- Rules ---
RULES_DIR="${E2E_DIR}/rules"
mkdir -p "$RULES_DIR"

cat > "$RULES_DIR/deny.yaml" << 'YAML'
- rule: Deny rm -rf
  desc: Block dangerous rm -rf commands
  condition: tool.name = "Bash" and tool.input_command contains "rm -rf"
  output: "DENY id=%correlation.id cmd=%tool.input_command"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Deny writes to etc
  desc: Block writes to /etc/ (and /private/etc/ on macOS where /etc is a symlink)
  condition: tool.name in ("Write", "Edit") and (tool.real_file_path startswith "/etc/" or tool.real_file_path startswith "/private/etc/")
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
YAML

cat > "$RULES_DIR/seen.yaml" << 'YAML'
- rule: Coding Agent Event Seen
  desc: Catch-all rule signaling evaluation complete
  condition: correlation.id > 0
  output: "id=%correlation.id"
  priority: DEBUG
  source: coding_agent
  tags: [coding_agent_seen]
YAML

# --- Helpers ---
cleanup() {
    [[ -n "$FALCO_PID" ]] && kill "$FALCO_PID" 2>/dev/null && wait "$FALCO_PID" 2>/dev/null
    rm -rf "$E2E_DIR"
}
trap cleanup EXIT

start_falco() {
    rm -f "$SOCK"
    falco -c "$ROOT_DIR/configs/falco.yaml" \
        -o "plugins[0].name=coding_agent" \
        -o "plugins[0].library_path=$PLUGIN_LIB" \
        -o "plugins[0].init_config={\"socket_path\":\"$SOCK\",\"http_port\":$HTTP_PORT}" \
        -o "load_plugins[0]=coding_agent" \
        -o "rules_files[0]=$RULES_DIR/deny.yaml" \
        -o "rules_files[1]=$RULES_DIR/seen.yaml" \
        -o "json_output=true" \
        -o "rule_matching=all" \
        -o "http_output.enabled=true" \
        -o "http_output.url=http://127.0.0.1:$HTTP_PORT" \
        --disable-source syscall \
        > "$E2E_DIR/falco.log" 2>&1 &
    FALCO_PID=$!

    # Wait for socket + HTTP server to be ready.
    local i=0
    while [[ ! -S "$SOCK" ]] && (( i < 40 )); do
        sleep 0.2
        ((i++))
    done
    # Extra wait for HTTP server bind.
    sleep 0.5

    if [[ ! -S "$SOCK" ]]; then
        echo "ERROR: Falco did not start (socket not found)" >&2
        echo "Falco log:" >&2
        cat "$E2E_DIR/falco.log" >&2
        return 1
    fi
}

run_hook() {
    local input="$1"
    echo "$input" | \
        CODING_AGENTS_KIT_SOCKET="$SOCK" \
        CODING_AGENTS_KIT_TIMEOUT_MS=5000 \
        "$HOOK" 2>/dev/null || true
}

pass() {
    echo "  PASS: $1"
    ((PASS++)) || true
}

fail() {
    echo "  FAIL: $1"
    echo "    expected: $2"
    echo "    got: $3"
    ((FAIL++)) || true
}

assert_decision() {
    local output="$1"
    local expected="$2"
    local msg="$3"
    if echo "$output" | grep -qF "\"permissionDecision\":\"$expected\""; then
        pass "$msg"
    else
        fail "$msg" "decision=$expected" "$output"
    fi
}

assert_reason_contains() {
    local output="$1"
    local needle="$2"
    local msg="$3"
    if echo "$output" | grep -qF "$needle"; then
        pass "$msg"
    else
        fail "$msg" "reason contains '$needle'" "$output"
    fi
}

make_input() {
    local tool_name="$1"
    local tool_input="$2"
    local cwd="${3:-/tmp}"
    local id="${4:-toolu_$(date +%s%N)}"
    echo "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"$tool_name\",\"tool_input\":$tool_input,\"session_id\":\"e2e-test\",\"cwd\":\"$cwd\",\"tool_use_id\":\"$id\"}"
}

# --- Start Falco ---
echo "Starting Falco with plugin..."
start_falco || exit 1
echo "Falco running (PID=$FALCO_PID, socket=$SOCK, http=$HTTP_PORT)"
echo ""

# --- Tests ---

echo "=== Deny: rm -rf ==="
out=$(run_hook "$(make_input Bash '{"command":"rm -rf /"}' /tmp toolu_deny_rmrf)")
assert_decision "$out" "deny" "rm -rf denied"
assert_reason_contains "$out" "Deny rm -rf" "deny reason mentions rule name"

echo "=== Deny: rm -rf (variant) ==="
out=$(run_hook "$(make_input Bash '{"command":"sudo rm -rf /home"}' /tmp toolu_deny_rmrf2)")
assert_decision "$out" "deny" "rm -rf variant denied"

echo "=== Allow: safe command ==="
out=$(run_hook "$(make_input Bash '{"command":"ls -la"}' /tmp toolu_allow_ls)")
assert_decision "$out" "allow" "ls allowed"

echo "=== Allow: echo command ==="
out=$(run_hook "$(make_input Bash '{"command":"echo hello"}' /tmp toolu_allow_echo)")
assert_decision "$out" "allow" "echo allowed"

echo "=== Deny: write to /etc/ ==="
out=$(run_hook "$(make_input Write '{"file_path":"/etc/passwd","content":"x"}' /tmp toolu_deny_etc)")
assert_decision "$out" "deny" "write to /etc denied"
assert_reason_contains "$out" "Deny writes to etc" "deny reason mentions rule name"

echo "=== Ask: write outside cwd ==="
out=$(run_hook "$(make_input Write '{"file_path":"/home/other/file.txt","content":"x"}' /tmp/myproject toolu_ask_outside)")
assert_decision "$out" "ask" "write outside cwd asks"
assert_reason_contains "$out" "Ask write outside cwd" "ask reason mentions rule name"

echo "=== Allow: write inside cwd ==="
out=$(run_hook "$(make_input Write '{"file_path":"/tmp/myproject/file.txt","content":"x"}' /tmp/myproject toolu_allow_inside)")
assert_decision "$out" "allow" "write inside cwd allowed"

echo "=== Allow: Read tool ==="
out=$(run_hook "$(make_input Read '{"file_path":"/tmp/test.txt"}' /tmp toolu_allow_read)")
assert_decision "$out" "allow" "read allowed"

echo "=== Allow: Grep tool ==="
out=$(run_hook "$(make_input Grep '{"pattern":"foo","path":"/tmp"}' /tmp toolu_allow_grep)")
assert_decision "$out" "allow" "grep allowed"

echo "=== Allow: MCP tool ==="
out=$(run_hook "$(make_input 'mcp__github__get_issue' '{"number":42}' /tmp toolu_allow_mcp)")
assert_decision "$out" "allow" "MCP tool allowed"

# --- Results ---
echo ""
echo "================================"
echo "E2E Results: $PASS passed, $FAIL failed"
echo "================================"

[[ "$FAIL" -eq 0 ]]
