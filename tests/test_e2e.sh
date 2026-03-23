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

- rule: Deny reading sensitive paths
  desc: Block reads from sensitive paths
  condition: tool.name = "Read" and (tool.real_file_path startswith "/etc/" or tool.real_file_path startswith "/private/etc/" or tool.real_file_path contains "/.ssh/" or tool.real_file_path contains "/.aws/")
  output: "Falco blocked reading %tool.real_file_path because it is a sensitive path"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Deny writing to ssh dir
  desc: Block writes to .ssh directories
  condition: tool.name in ("Write", "Edit") and tool.real_file_path contains "/.ssh/"
  output: "Falco blocked writing to %tool.real_file_path because .ssh is a sensitive directory"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]

- rule: Monitor outside cwd
  desc: Log all file access outside working directory (informational, no verdict)
  condition: tool.name in ("Write", "Edit", "Read") and tool.real_file_path != "" and not tool.real_file_path startswith val(agent.real_cwd)
  output: "File access outside cwd | file=%tool.real_file_path cwd=%agent.real_cwd"
  priority: NOTICE
  source: coding_agent
  tags: []
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
    # Use inline config overrides so the test does not depend on an installed
    # config at ~/.coding-agents-kit/. This makes the test self-contained.
    falco \
        -o "engine.kind=nodriver" \
        -o "config_files=" \
        -o "plugins[0].name=coding_agent" \
        -o "plugins[0].library_path=$PLUGIN_LIB" \
        -o "plugins[0].init_config={\"socket_path\":\"$SOCK\",\"http_port\":$HTTP_PORT,\"mode\":\"$mode\"}" \
        -o "load_plugins[0]=coding_agent" \
        -o "rules_files[0]=$RULES_DIR/deny.yaml" \
        -o "rules_files[1]=$RULES_DIR/seen.yaml" \
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

echo "=== Deny: read sensitive path ==="
out=$(run_hook "$(make_input Read '{"file_path":"/etc/shadow"}' /tmp toolu_deny_read_etc)")
assert_decision "$out" "deny" "read /etc/shadow denied"
assert_reason_contains "$out" "Deny reading sensitive paths" "deny reason mentions read rule name"

echo "=== Deny: read ssh key ==="
out=$(run_hook "$(make_input Read '{"file_path":"/home/user/.ssh/id_rsa"}' /tmp toolu_deny_read_ssh)")
assert_decision "$out" "deny" "read .ssh/id_rsa denied"

echo "=== Allow: read safe file ==="
out=$(run_hook "$(make_input Read '{"file_path":"/tmp/safe.txt"}' /tmp toolu_allow_read_safe)")
assert_decision "$out" "allow" "read safe file allowed"

echo "=== Deny: append_output text in reason ==="
# Verify the append_output "For AI Agents" instruction appears in deny reasons.
out=$(run_hook "$(make_input Bash '{"command":"rm -rf /tmp/nuke"}' /tmp toolu_deny_append)")
assert_reason_contains "$out" "For AI Agents" "append_output instruction in deny reason"
assert_reason_contains "$out" "correlation=" "correlation.id in deny reason"

echo "=== Deny: write to /etc does not get ask (escalation) ==="
# Write to /etc/ is both outside cwd and a sensitive path — deny must win over ask.
out=$(run_hook "$(make_input Write '{"file_path":"/etc/hosts","content":"x"}' /tmp/myproject toolu_escalation)")
assert_decision "$out" "deny" "deny wins over ask (verdict escalation)"

# --- Edit tool (same rules as Write, verify both match) ---

echo "=== Deny: edit to /etc/ ==="
out=$(run_hook "$(make_input Edit '{"file_path":"/etc/passwd","old_string":"x","new_string":"y"}' /tmp toolu_deny_edit_etc)")
assert_decision "$out" "deny" "edit /etc denied"

echo "=== Ask: edit outside cwd ==="
out=$(run_hook "$(make_input Edit '{"file_path":"/home/other/file.txt","old_string":"x","new_string":"y"}' /tmp/myproject toolu_ask_edit_outside)")
assert_decision "$out" "ask" "edit outside cwd asks"

echo "=== Allow: edit inside cwd ==="
out=$(run_hook "$(make_input Edit '{"file_path":"/tmp/myproject/file.txt","old_string":"x","new_string":"y"}' /tmp/myproject toolu_allow_edit_inside)")
assert_decision "$out" "allow" "edit inside cwd allowed"

# --- Sensitive directory variants ---

echo "=== Deny: write to .ssh/ ==="
out=$(run_hook "$(make_input Write '{"file_path":"/home/user/.ssh/authorized_keys","content":"x"}' /tmp toolu_deny_write_ssh)")
assert_decision "$out" "deny" "write to .ssh denied"

echo "=== Deny: edit .ssh/ ==="
out=$(run_hook "$(make_input Edit '{"file_path":"/home/user/.ssh/config","old_string":"x","new_string":"y"}' /tmp toolu_deny_edit_ssh)")
assert_decision "$out" "deny" "edit .ssh denied"

echo "=== Deny: read .aws/ ==="
out=$(run_hook "$(make_input Read '{"file_path":"/home/user/.aws/credentials"}' /tmp toolu_deny_read_aws)")
assert_decision "$out" "deny" "read .aws/credentials denied"

# --- Bash edge cases ---

echo "=== Allow: rm without -rf (not dangerous) ==="
out=$(run_hook "$(make_input Bash '{"command":"rm file.txt"}' /tmp toolu_allow_rm_safe)")
assert_decision "$out" "allow" "rm without -rf allowed"

echo "=== Deny: rm -rf in chained command ==="
out=$(run_hook "$(make_input Bash '{"command":"echo yes && rm -rf /tmp/target"}' /tmp toolu_deny_rmrf_chain)")
assert_decision "$out" "deny" "rm -rf in chained command denied"

# --- Tools that should always allow (no matching rules) ---

echo "=== Allow: Agent tool ==="
out=$(run_hook "$(make_input Agent '{"prompt":"do something","description":"test"}' /tmp toolu_allow_agent)")
assert_decision "$out" "allow" "Agent tool allowed (no rules match)"

echo "=== Allow: Glob tool ==="
out=$(run_hook "$(make_input Glob '{"pattern":"*.rs"}' /tmp toolu_allow_glob)")
assert_decision "$out" "allow" "Glob tool allowed (no rules match)"

echo "=== Allow: WebSearch tool ==="
out=$(run_hook "$(make_input WebSearch '{"query":"rust programming"}' /tmp toolu_allow_websearch)")
assert_decision "$out" "allow" "WebSearch tool allowed (no rules match)"

# --- Path resolution edge cases ---

echo "=== Deny: write with path traversal to /etc/ ==="
# /tmp/myproject/../../etc/passwd resolves to /etc/passwd
out=$(run_hook "$(make_input Write '{"file_path":"/tmp/myproject/../../etc/passwd","content":"x"}' /tmp/myproject toolu_deny_traversal)")
assert_decision "$out" "deny" "path traversal to /etc/ denied"

echo "=== Allow: relative path inside cwd ==="
out=$(run_hook "$(make_input Write '{"file_path":"src/main.rs","content":"x"}' /tmp/myproject toolu_allow_relative)")
assert_decision "$out" "allow" "relative path inside cwd allowed"

# --- Monitor rule (no verdict tag — still allows) ---

echo "=== Allow: read outside cwd triggers monitor but still allows ==="
# The Monitor outside cwd rule fires (NOTICE, empty tags) but doesn't affect the verdict.
out=$(run_hook "$(make_input Read '{"file_path":"/tmp/other/data.txt"}' /tmp/myproject toolu_monitor_read)")
assert_decision "$out" "allow" "monitor-only rule does not block"

# --- MCP tool field extraction ---

echo "=== Allow: MCP tool with server name ==="
out=$(run_hook "$(make_input 'mcp__ide__getDiagnostics' '{"uri":"file:///tmp/test.ts"}' /tmp toolu_allow_mcp_ide)")
assert_decision "$out" "allow" "MCP tool with server name allowed"

# --- Monitor mode tests ---
# Restart Falco in monitor mode: rules evaluate and log, but all verdicts
# resolve as allow. This verifies the broker's monitor mode branches.
echo ""
echo "=== Restarting Falco in monitor mode ==="
start_falco monitor || exit 1
echo "Falco running in monitor mode (PID=$FALCO_PID)"
echo ""

echo "=== Monitor: rm -rf resolves as allow ==="
out=$(run_hook "$(make_input Bash '{"command":"rm -rf /"}' /tmp toolu_mon_rmrf)")
assert_decision "$out" "allow" "monitor mode: rm -rf allowed (not enforced)"

echo "=== Monitor: write to /etc/ resolves as allow ==="
out=$(run_hook "$(make_input Write '{"file_path":"/etc/passwd","content":"x"}' /tmp toolu_mon_etc)")
assert_decision "$out" "allow" "monitor mode: write /etc/ allowed (not enforced)"

echo "=== Monitor: write outside cwd resolves as allow ==="
out=$(run_hook "$(make_input Write '{"file_path":"/home/other/file.txt","content":"x"}' /tmp/myproject toolu_mon_outside)")
assert_decision "$out" "allow" "monitor mode: write outside cwd allowed (not enforced)"

echo "=== Monitor: safe command still allowed ==="
out=$(run_hook "$(make_input Bash '{"command":"ls -la"}' /tmp toolu_mon_ls)")
assert_decision "$out" "allow" "monitor mode: safe command allowed"

# --- Results ---
echo ""
echo "================================"
echo "E2E Results: $PASS passed, $FAIL failed"
echo "================================"

[[ "$FAIL" -eq 0 ]]
