#!/usr/bin/env bash
#
# Integration tests for the interceptor.
# Requires: python3, the built interceptor binary.
#
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." &>/dev/null && pwd)"
# Allow overriding the hook binary via HOOK env var (for testing C vs Rust).
HOOK="${HOOK:-${ROOT_DIR}/hooks/claude-code/target/release/claude-interceptor}"
MOCK="${ROOT_DIR}/tests/mock_broker.py"

if [[ ! -x "$HOOK" ]]; then
    echo "ERROR: interceptor not found at $HOOK" >&2
    echo "  Rust: cd hooks/claude-code && cargo build --release" >&2
    echo "  C:    cd hooks && make linux" >&2
    exit 1
fi
SOCK="/tmp/cak-test-$$.sock"
PASS=0
FAIL=0

cleanup() {
    rm -f "$SOCK"
}
trap cleanup EXIT

# Start mock broker, wait for socket, run hook, collect output, stop broker.
# Usage: result=$(run_test <mode> <stdin_json> [extra_env...])
run_test() {
    local mode="$1"
    local input="$2"
    shift 2

    rm -f "$SOCK"
    python3 "$MOCK" "$SOCK" "$mode" > /dev/null 2>&1 &
    local pid=$!

    # Wait for socket.
    local i=0
    while [[ ! -S "$SOCK" ]] && (( i < 20 )); do
        sleep 0.1
        ((i++))
    done

    local out
    out=$(echo "$input" | env CODING_AGENTS_KIT_SOCKET="$SOCK" "$@" "$HOOK" 2>/dev/null) || true

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$SOCK"
    echo "$out"
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

assert_contains() {
    if echo "$1" | grep -qF "$2"; then
        pass "$3"
    else
        fail "$3" "contains '$2'" "$1"
    fi
}

SAMPLE='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"test-sess","cwd":"/tmp","tool_use_id":"toolu_test123"}'

# ------------------------------------------------------------------
echo "=== Allow verdict ==="
out=$(run_test allow "$SAMPLE")
assert_contains "$out" '"permissionDecision":"allow"' "allow verdict"

echo "=== Deny verdict ==="
out=$(run_test deny "$SAMPLE")
assert_contains "$out" '"permissionDecision":"deny"' "deny verdict"
assert_contains "$out" 'blocked by test rule' "deny reason"

echo "=== Ask verdict ==="
out=$(run_test ask "$SAMPLE")
assert_contains "$out" '"permissionDecision":"ask"' "ask verdict"
assert_contains "$out" 'requires confirmation' "ask reason"

echo "=== Broker unreachable (fail-closed) ==="
rm -f "$SOCK"
out=$(echo "$SAMPLE" | env CODING_AGENTS_KIT_SOCKET="$SOCK" "$HOOK" 2>/dev/null) || true
assert_contains "$out" '"permissionDecision":"deny"' "fail-closed deny"

echo "=== Bad JSON response ==="
out=$(run_test bad_json "$SAMPLE")
assert_contains "$out" '"permissionDecision":"deny"' "bad_json deny"

echo "=== Wrong ID response ==="
out=$(run_test wrong_id "$SAMPLE")
assert_contains "$out" '"permissionDecision":"deny"' "wrong_id deny"

echo "=== Timeout ==="
out=$(run_test "slow:3" "$SAMPLE" env CODING_AGENTS_KIT_TIMEOUT_MS=200)
assert_contains "$out" '"permissionDecision":"deny"' "timeout deny"

echo "=== Broker closes connection ==="
out=$(run_test close "$SAMPLE")
assert_contains "$out" '"permissionDecision":"deny"' "close deny"

echo "=== Empty stdin ==="
rc=0
echo -n "" | "$HOOK" 2>/dev/null || rc=$?
if [[ "$rc" -eq 2 ]]; then pass "empty stdin exit 2"; else fail "empty stdin exit 2" "exit 2" "exit $rc"; fi

echo "=== Malformed JSON ==="
rc=0
echo 'not json' | "$HOOK" 2>/dev/null || rc=$?
if [[ "$rc" -eq 2 ]]; then pass "malformed JSON exit 2"; else fail "malformed JSON exit 2" "exit 2" "exit $rc"; fi

echo "=== Missing tool_name (valid JSON, no broker) ==="
# Interceptor no longer validates tool_name — it passes through to broker.
# With no broker running, this is a broker error → fail-closed deny.
rm -f "$SOCK"
out=$(echo '{"hook_event_name":"PreToolUse","tool_input":{}}' | env CODING_AGENTS_KIT_SOCKET="$SOCK" "$HOOK" 2>/dev/null) || true
assert_contains "$out" '"permissionDecision":"deny"' "missing tool_name deny (no broker)"

echo "=== Write tool path ==="
write_input='{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/test.txt","content":"hello"},"session_id":"s1","cwd":"/tmp","tool_use_id":"t2"}'
out=$(run_test allow "$write_input")
assert_contains "$out" '"permissionDecision":"allow"' "write tool"

echo "=== MCP tool ==="
mcp_input='{"hook_event_name":"PreToolUse","tool_name":"mcp__github__create_issue","tool_input":{"title":"test"},"session_id":"s1","cwd":"/tmp","tool_use_id":"t3"}'
out=$(run_test allow "$mcp_input")
assert_contains "$out" '"permissionDecision":"allow"' "MCP tool"

echo "=== Large tool_input ==="
large_cmd=$(python3 -c "print('x' * 60000)")
large_input="{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$large_cmd\"},\"session_id\":\"s1\",\"cwd\":\"/tmp\",\"tool_use_id\":\"t4\"}"
out=$(run_test allow "$large_input")
assert_contains "$out" '"permissionDecision":"allow"' "large input"

echo "=== Nested key spoofing (find_key must only match root-level keys) ==="
# tool_input contains a "tool_name" key that should NOT override the real top-level one.
spoof_input='{"hook_event_name":"PreToolUse","tool_input":{"tool_name":"SPOOFED","command":"ls"},"tool_name":"Bash","session_id":"s1","cwd":"/tmp","tool_use_id":"t5"}'
out=$(run_test allow "$spoof_input")
assert_contains "$out" '"permissionDecision":"allow"' "nested key spoofing"

echo "=== JSON escape in command ==="
# Command contains a literal quote character (escaped in JSON as \").
# Verify the hook doesn't crash and round-trips correctly.
esc_input='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo \"hello world\""},"session_id":"s1","cwd":"/tmp","tool_use_id":"t6"}'
out=$(run_test allow "$esc_input")
assert_contains "$out" '"permissionDecision":"allow"' "escaped command"

echo "=== Path traversal normalization ==="
# file_path with .. components should be normalized in the wire protocol.
traversal_input='{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"subdir/../../etc/shadow","content":"x"},"session_id":"s1","cwd":"/home/user","tool_use_id":"t7"}'
out=$(run_test allow "$traversal_input")
assert_contains "$out" '"permissionDecision":"allow"' "path traversal normalization"

# ------------------------------------------------------------------
echo ""
echo "================================"
echo "Results: $PASS passed, $FAIL failed"
echo "================================"

[[ "$FAIL" -eq 0 ]]
