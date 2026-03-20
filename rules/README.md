# Rules

Falco rules for coding-agents-kit. These rules define security policies that govern what coding agents can do.

## Structure

```
rules/
├── default/
│   └── coding_agents_rules.yaml   # Default ruleset shipped with the project
├── user/                           # Custom user rules
│   └── .gitkeep
├── seen.yaml                       # Catch-all rule (required, always loaded last)
└── README.md
```

### `default/coding_agents_rules.yaml`

The default security policies shipped with coding-agents-kit. This file is **overwritten on upgrade** — do not edit it directly. To customize behavior, add rules in the `user/` directory instead.

### `user/`

Place your custom rules here. Files in this directory are **preserved across upgrades**. You can:

- Add new rules for your specific needs
- Override default rules using Falco's `override` mechanism (append/replace conditions, change priorities)
- Add project-specific allow/deny lists

### `seen.yaml`

A mandatory catch-all rule that fires for every coding agent event. It signals to the plugin broker that rule evaluation is complete for a given tool call. **Do not remove or modify this file** — the verdict resolution mechanism depends on it.

This file must always be loaded **after** all other rule files. The loading order is configured in `falco.coding_agents_plugin.yaml`.

## Rule Tags

Rules use tags to communicate verdicts to the plugin broker:

| Tag | Effect |
|-----|--------|
| `coding_agent_deny` | Block the tool call |
| `coding_agent_ask` | Require user confirmation |
| `coding_agent_seen` | Signal evaluation complete (used only by `seen.yaml`) |

When multiple rules match the same event, verdict escalation applies: **deny > ask > allow**.

## Writing Rules

Rules use the standard [Falco rule language](https://falco.org/docs/rules/). Available fields:

| Field | Description |
|-------|-------------|
| `correlation.id` | Broker-assigned unique ID (used for verdict correlation) |
| `agent.name` | Coding agent identifier (e.g., `claude_code`) |
| `agent.session_id` | Session identifier |
| `agent.cwd` | Working directory (raw) |
| `agent.real_cwd` | Working directory (resolved, absolute) |
| `tool.use_id` | Unique identifier for this tool call |
| `tool.name` | Tool name (e.g., `Bash`, `Write`, `Edit`, `Read`) |
| `tool.input` | Full tool input as JSON |
| `tool.input_command` | Shell command (Bash only) |
| `tool.file_path` | Target file path (raw, Write/Edit/Read only) |
| `tool.real_file_path` | Target file path (resolved, absolute, Write/Edit/Read only) |
| `tool.mcp_server` | MCP server name (MCP tools only) |

All rules must:
- Set `source: coding_agent`
- Include `correlation=%correlation.id` in the structured fields (required for verdict correlation)
- Use the appropriate verdict tag (`coding_agent_deny` or `coding_agent_ask`)
- Follow the output convention described below

### Output Convention

The rule `output:` field is the primary message the coding agent receives as the verdict reason. It uses a two-part format:

```
<LLM-friendly message> | <structured fields>
```

**LLM-friendly message** (before the pipe): A clear, self-contained sentence explaining what happened and why. Must start with "Falco" to attribute the enforcement (e.g., "Falco blocked...", "Falco requires confirmation..."). The coding agent presents this to the user. Use resolved field values (e.g., `%tool.real_file_path`) so the message is informative. Avoid jargon or raw field names.

**Structured fields** (after the pipe): Key=value pairs for logging, auditing, and debugging. Always include `correlation=%correlation.id`.

The broker passes the full rendered output as the verdict reason, prefixed by the rule name: `"Rule Name: <rendered output>"`. So the coding agent sees:

```
Deny writing to sensitive paths: Falco blocked writing to /etc/passwd because it is a sensitive path | file=/etc/passwd cwd=/home/user/project ...
```

### Example

```yaml
- rule: Deny pipe to shell
  desc: Block piping content to shell interpreters
  condition: >
    tool.name = "Bash"
    and (tool.input_command contains "| sh"
         or tool.input_command contains "| bash")
  output: >
    Falco blocked piping to a shell interpreter |
    command=%tool.input_command
    correlation=%correlation.id agent=%agent.name tool=%tool.name
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]
```

### Tips

- Use `val()` for field-to-field comparisons: `tool.real_file_path startswith val(agent.real_cwd)`
- Use `basename()` to match file names: `basename(tool.file_path) = ".env"`
- Use `real_*` fields for security policy matching (resolved paths)
- Use raw fields (`agent.cwd`, `tool.file_path`) for display and audit
