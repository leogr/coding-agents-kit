# Codex CLI Compatibility Analysis

Analysis of the OpenAI Codex CLI (`github.com/openai/codex`) hook system for compatibility with coding-agents-kit. Based on direct inspection of the `codex-rs/hooks/` crate from the live repository (March 2026).

## Key Finding

**Codex has a hook system nearly identical to Claude Code's.** The `codex-rs/hooks/` crate implements `PreToolUse` hooks with the same pattern: an external command receives JSON on stdin, returns a verdict on stdout.

## Input Format Comparison

| Field | Claude Code | Codex CLI | Compatible? |
|-------|------------|-----------|-------------|
| `session_id` | string | string | Same |
| `cwd` | string | string | Same |
| `hook_event_name` | `"PreToolUse"` | `"PreToolUse"` | Same |
| `tool_name` | `"Bash"`, `"Write"`, etc. | `"Bash"` (hardcoded) | Partial |
| `tool_input.command` | string | string | Same for Bash |
| `tool_use_id` | string | string | Same |
| `transcript_path` | string | nullable string | Same |
| `permission_mode` | string | string | Same |
| `model` | not sent | string | Codex-only |
| `turn_id` | not sent | string | Codex-only |

## Output Format Comparison

| Field | Claude Code | Codex CLI | Compatible? |
|-------|------------|-----------|-------------|
| `hookSpecificOutput.permissionDecision` | `"allow"`, `"deny"`, `"ask"` | `"deny"` only | **Critical difference** |
| `hookSpecificOutput.permissionDecisionReason` | string | string | Same |
| `hookSpecificOutput.additionalContext` | supported | **rejected** (fails open) | Incompatible |
| `hookSpecificOutput.updatedInput` | not used | **rejected** (fails open) | Incompatible |
| Exit code 2 | blocks tool call | blocks tool call | Same |

### Critical: Codex only supports `deny`, not `ask`

The test `unsupported_permission_decision_fails_open` explicitly shows that `"ask"` is treated as an error and **fails open** (the tool call proceeds). Codex also doesn't support `"allow"` as an explicit verdict — empty/no-output means allow.

## Tool Types

Codex constructs the `PreToolUseCommandInput` with `tool_name: "Bash"` hardcoded. Looking at the `HookToolKind` enum, Codex supports: `Function`, `Custom`, `LocalShell`, `Mcp`. But the pre-tool-use hook input appears to only fire for shell commands (the `tool_input` only has a `command` field).

This means Codex hooks see shell commands but likely **not** file writes or reads as separate tool types — unlike Claude Code where `Write`, `Edit`, `Read` are distinct tools with `file_path`.

## Implications for coding-agents-kit

### What works out of the box

- The event field schema (`coding_agent` source) is generic enough
- `agent.name` can distinguish Codex from Claude Code
- Bash-related fields (`tool.name = "Bash"`, `tool.input_command`) work for Codex
- The wire protocol (interceptor → broker → Falco → verdict) is agent-agnostic
- Deny rules for shell commands work identically

### What needs adaptation

1. **No `ask` verdict** — Codex only supports `deny` or allow (empty). The `coding_agent_ask` tag would need to be mapped to either deny or allow for Codex. This is a policy decision per deployment.

2. **Only shell commands** — Codex hooks only fire for shell tool calls. File writes/reads are not intercepted at the hook level. Rules matching `tool.name = "Write"` or `tool.name = "Read"` would never trigger for Codex.

3. **No `file_path` field** — Since only shell commands are hooked, `tool.file_path` / `tool.real_file_path` are never populated. Path-based rules (sensitive paths, outside-cwd detection) would need to be rewritten as shell command pattern matching for Codex.

4. **`tool_name` is always "Bash"** — Tool-type rules are limited to Bash for Codex.

## Recommended Approach

### Architecture: single plugin, separate interceptors

No schema changes needed. The same Falco plugin and rules work, just with a subset of functionality for Codex.

- A **Codex interceptor** (`hooks/codex/`) that maps Codex's hook JSON to the same wire protocol
- A **verdict mapper** in the interceptor that translates `ask` → `deny` (or `allow`, configurable) since Codex doesn't support the ask verdict
- **Shared rules** work for Bash commands; path-based rules are Claude Code-only
- `agent.name = "codex"` distinguishes the agent in rules

### What NOT to do

- Do NOT change the plugin or wire protocol
- Do NOT add Codex-specific fields to the plugin (the existing fields cover Codex's input)
- Do NOT fork the rule engine — use `agent.name` in conditions for agent-specific rules

## Source Files Referenced

- `codex-rs/hooks/src/types.rs` — HookPayload, HookResult, HookEvent, HookToolKind
- `codex-rs/hooks/src/schema.rs` — PreToolUseCommandInput (wire format)
- `codex-rs/hooks/src/events/pre_tool_use.rs` — PreToolUse execution, output parsing, verdict handling
- `codex-rs/hooks/src/engine/output_parser.rs` — Output format parsing, unsupported verdict handling
