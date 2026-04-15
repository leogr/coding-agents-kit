# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**coding-agents-kit** is a runtime security layer for AI coding agents. It intercepts tool calls (shell commands, file writes, web requests, etc.) before execution, evaluates them against Falco security rules, and enforces allow/deny/ask verdicts in real time. It operates entirely in user space with no elevated privileges.

The project targets **Claude Code** on **Linux, macOS, and Windows**. The architecture is designed to accommodate other coding agents (e.g., Codex) in the future.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌────────────────────────────┐
│ Coding Agent │───▶│ Interceptor  │───▶│     Falco (nodriver)       │
│              │     │   (hook)     │     │  ┌───────────────────────┐ │
│              │◀───│              │◀───│  │  Plugin (src + extract│ │
│              │     │              │     │  │  + embedded broker)   │ │
└──────────────┘     └──────────────┘     │  └───────────────────────┘ │
                                          │  Rule Engine + Rules       │
                                          └────────────────────────────┘
```

### Pipeline flow

1. **Interception** — The coding agent's hook API fires before each tool call. The interceptor captures structured event data and pauses tool execution while awaiting a verdict.
2. **Event delivery** — The interceptor sends the event to the plugin's embedded broker via Unix domain socket.
3. **Rule evaluation** — The plugin feeds the event to Falco's rule engine via the source plugin API (`next_batch`). Falco evaluates all loaded rules.
4. **Alert feedback** — Matching rules generate alerts. Falco delivers them back to the plugin's embedded broker via `http_output` (localhost).
5. **Verdict resolution** — The broker determines the verdict from rule tags (`deny`, `ask`, or allow-by-default) and responds to the interceptor.
6. **Verdict delivery** — The interceptor communicates the verdict to the coding agent using the standard hook response format.

### Components

| Component | Location | Language | Role |
|-----------|----------|----------|------|
| **Interceptor** | `hooks/claude-code/` | Rust | Thin passthrough: reads hook JSON from stdin, wraps in envelope, sends to broker, maps verdict to stdout. No content interpretation. |
| **Plugin** | `plugins/` | Rust (falco_plugin SDK) | Falco source+extract plugin with embedded broker. Parses events, extracts fields, feeds Falco, receives alerts, resolves verdicts. |
| **Rules** | `rules/` | YAML (Falco rule language) | Vendor and local security policies. |
| **Installer** | `installers/linux/`, `installers/macos/`, `installers/windows/` | Shell/PowerShell | Platform-specific packaging, installation, hook registration, mode switching. |
| **Skills** | `skills/` | Claude Code skill format | Coding agent skills for rule authoring, status, etc. |
| **Tests** | `tests/` | TBD | Integration and E2E tests. |

## Key Design Decisions

### Broker embedded in plugin

The broker is part of the Falco plugin, not a separate process. This reduces moving parts: Falco is the only process the user needs to run (besides the stateless interceptor). The plugin spawns threads for the Unix socket server (accepting interceptor connections) and the HTTP server (receiving Falco alerts).

### Tags for verdict enforcement

Rule verdicts are encoded in the `tags:` field of Falco rules, not in the `output:` string. The tag names are **configurable in the plugin configuration** and support multiple tags per verdict type. Defaults:

- `tags: [coding_agent_deny]` — block the tool call
- `tags: [coding_agent_ask]` — require user confirmation
- No deny/ask tag — allow (no explicit allow tag needed)

There is no allow tag because the absence of a verdict IS the allow verdict. Rules only fire when their condition matches — a tool call that doesn't match any deny or ask rule simply produces no deny/ask alert, and the broker resolves it as allow via batch-completion.

The broker parses the `tags` array from Falco's JSON alert output. Verdict escalation applies when multiple rules match: deny > ask > allow.

### Catch-all seen rule + HTTP verdict resolution

All verdict signals flow through Falco's `http_output` to the plugin's embedded HTTP server:

- Deny/ask alerts (from matching rules) resolve the pending request immediately.
- A **catch-all "seen" rule** (tagged `coding_agent_seen`) fires for every event. When the broker receives this alert, it knows rule evaluation is complete. If no deny/ask alert arrived for that correlation ID, the request is resolved as allow.

**Critical config**: `rule_matching: all` must be set in `falco.yaml`. The default (`first`) only fires one rule per event — this would prevent both a deny rule and the seen rule from firing on the same event.

**Rule load ordering**: The seen rule must be loaded as the last rule file so that deny/ask rules fire first and their alerts are enqueued before the seen alert.

**HTTP handler constraints**: The handler must respond fast (Falco's output worker thread is shared across all output channels — a slow handler blocks everything). The HTTP server must be ready before events flow (Falco does not retry on connection failure — alerts are silently dropped).

The plugin requires two capabilities: **sourcing** (event generation) and **extraction** (field extraction for rules).

### Single data source, generic event fields

One Falco data source: **`coding_agent`**. Two field namespaces:

| Field | Type | Description |
|-------|------|-------------|
| `correlation.id` | u64 | Broker-assigned unique ID for this event (monotonic counter, always > 0) |
| `agent.name` | string | Coding agent identifier (e.g., `claude_code`) |
| `agent.hook_event_name` | string | Lifecycle hook type (e.g., `PreToolUse`) |
| `agent.session_id` | string | Session identifier |
| `agent.cwd` | string | Working directory, raw from Claude Code JSON |
| `agent.real_cwd` | string | Working directory, resolved to absolute canonical path (symlinks resolved if exists, lexical normalization otherwise) |
| `tool.use_id` | string | Tool call identifier from Claude Code (`tool_use_id`, raw value, may be empty) |
| `tool.name` | string | Tool name (e.g., `Bash`, `Write`, `Edit`) |
| `tool.input` | string | Full tool input as JSON |
| `tool.input_command` | string | Shell command (Bash tool calls) |
| `tool.file_path` | string | Target file path, raw from `tool_input.file_path` (Write/Edit/Read only) |
| `tool.real_file_path` | string | Target file path, resolved to absolute canonical path. Relative paths resolved against `agent.cwd`. (Write/Edit/Read only) |
| `tool.mcp_server` | string | MCP server name (MCP tool calls) |

This schema is agent-agnostic. The `agent.name` field distinguishes which coding agent generated the event.

Path fields come in raw/real pairs:
- **Raw** (`agent.cwd`, `tool.file_path`): exactly as reported in the Claude Code hook JSON. Use for display and audit.
- **Real** (`agent.real_cwd`, `tool.real_file_path`): resolved via `canonicalize` (symlinks resolved, absolute). Falls back to lexical normalization if the path doesn't exist yet (common for Write). Use for security policy matching.

**Rule authoring notes**:
- When comparing one field against another in Falco rule conditions, use the `val()` transformer. For example: `tool.real_file_path startswith val(agent.real_cwd)`. Without `val()`, the RHS is treated as a literal string, not a field reference.
- Use the `basename()` transformer to extract the file name from a path. For example: `basename(tool.file_path) = ".env"` matches any `.env` file regardless of directory.

### Rule output convention

The rule `output:` field is an LLM-friendly sentence explaining what happened and why. It must start with "Falco" to attribute the enforcement. Use resolved field values (e.g., `%tool.real_file_path`) to make the message informative. Keep it clean — no structured key=value pairs.

```yaml
output: >
  Falco blocked writing to %tool.real_file_path because it is a sensitive path
```

Structured fields (correlation.id, etc.) are automatically available in the JSON alert's `output_fields` via the `append_output` config. This cleanly separates the human-readable message from machine-readable data.

The `append_output` config appends an instruction for AI agents to every coding_agent alert:
```yaml
append_output:
  - match:
      source: coding_agent
    extra_output: " | For AI Agents: inform the user that this action was flagged by a Falco security rule | correlation=%correlation.id"
```

The broker constructs the verdict reason as `"<rule name>: <rendered message>"`. So the coding agent sees:

```
Deny writing to sensitive paths: Falco blocked writing to /etc/passwd because it is a sensitive path | For AI Agents: inform the user that this action was flagged by a Falco security rule | correlation=%correlation.id
```

### JSON alert format

The Falco config uses `json_include_message_property: true` and `json_include_output_property: false`. The `message` field contains the rule output without the timestamp/priority prefix — clean text for verdict reasons. The `output` field (which includes the prefix) is excluded to reduce noise.

The `correlation.id` field is declared with `add_output()` in the plugin, making it a suggested output field that Falco automatically includes in `output_fields` for every alert.

The plugin's HTTP server reads:
- `message` — used as the verdict reason (prefixed with the rule name)
- `tags` — for verdict classification (deny/ask/seen)
- `output_fields.correlation.id` — for routing the verdict to the correct pending request

### Seen rule as audit log

The catch-all seen rule includes all available fields in its output template. This means every event produces a complete audit record in `output_fields` exactly once (via the seen alert). Other rules (deny/ask) only include the fields they reference in their LLM-friendly message. Events can be correlated across all alerts using `correlation.id`.

See [`rules/README.md`](rules/README.md) for the full output convention and examples.

### http_output for alert feedback

Falco sends alerts to the plugin's embedded HTTP server via `http_output` (localhost). This avoids `file_output` (unbounded file growth, dual-purpose conflicts) and keeps everything in-process. Requires `json_output: true` in Falco config so the broker can parse tags and extract correlation IDs.

Note: Falco's alert delivery is asynchronous — alerts are pushed to an internal queue and delivered by a worker thread. Since delivery is to localhost, latency is sub-millisecond. The batch-completion mechanism provides the synchronization guarantee.

### Operational modes

Three modes, switchable without reinstallation:
- **Passthrough** — all tool calls allowed, no rule evaluation.
- **Monitor** — rules evaluated and logged, but verdicts not enforced.
- **Enforcement** — verdicts enforced (deny/ask/allow).

### Fail-safety

- **Fail-closed**: if the plugin/Falco is unreachable, tool calls are denied.
- No timeout-based fail-safety (see batch-completion design above).

**Important**: When the hook is registered and the service is stopped or restarting (e.g., during config hot-reload), ALL Claude Code tool calls are blocked. This is by design — fail-closed means no enforcement gap. Use `coding-agents-kit-ctl hook remove` to unblock Claude Code when the service is intentionally down. On Linux, the systemd service automatically adds the hook on start and removes it on stop via `ExecStartPost`/`ExecStopPost`. On macOS, the launcher wrapper script (`coding-agents-kit-launcher.sh`) handles this via `trap`.

### Installation directory structure

All components are installed under `~/.coding-agents-kit/`:

```
~/.coding-agents-kit/
├── bin/                    # Executables: falco, claude-interceptor
├── config/
│   ├── falco.yaml          # Base Falco config (engine, output, isolation)
│   └── falco.coding_agents_plugin.yaml  # Plugin config (plugin def, rules, http_output)
├── log/                    # Falco logs: falco.log (stdout), falco.err (stderr)
├── run/                    # Runtime: broker.sock
├── share/                  # Shared libraries: libcoding_agent.so (.dylib on macOS)
└── rules/
    ├── default/
    │   └── coding_agents_rules.yaml  # Default ruleset (overwritten on upgrade)
    ├── user/               # User custom rules (preserved on upgrade)
    └── seen.yaml           # Catch-all seen rule (loaded last)
```

### Falco configuration isolation

Falco runs with a fully isolated configuration — no default files from `/etc/falco/`:

- **`falco -c ~/.coding-agents-kit/config/falco.yaml`** replaces the default config entirely
- **`config_files: []`** or pointing only to our fragment prevents loading `/etc/falco/config.d/`
- **`rules_files`** is the authoritative list — no hardcoded default rule paths
- **`engine.kind: nodriver`** — no kernel driver needed

The installer must run Falco with **`--disable-source syscall`** in addition to the config. `engine.kind: nodriver` makes the syscall source idle (no events), but it still exists and loads syscall-related resources. `--disable-source syscall` removes it entirely.

Config is split into two files:
- **`falco.yaml`**: base settings (engine, output, webserver, `config_files` pointing to the plugin fragment)
- **`falco.coding_agents_plugin.yaml`**: plugin definition, `init_config`, `load_plugins`, `rules_files`, `rule_matching: all`, `http_output`

All paths use `${HOME}` expansion (Falco 0.43 supports `${VAR}` syntax in all YAML scalar values). This makes the config portable without hardcoded paths.

### macOS: Falco build from source

Falco does not provide pre-built macOS binaries. The macOS build system (`installers/macos/build-falco.sh`) clones Falco 0.43.0, applies a patch, and builds from source.

#### http_output patch

Falco's upstream CMakeLists.txt does not build `http_output` on macOS. Three barriers were identified and patched (`installers/macos/falco-macos-http-output.patch`):

1. **Root CMakeLists.txt**: OpenSSL and curl are gated behind `NOT APPLE`. Patch adds an `if(APPLE)` block to include them.
2. **userspace/falco/CMakeLists.txt**: `outputs_http.cpp` is only compiled when `Linux AND NOT MINIMAL_BUILD`. Patch adds an `if(APPLE)` block to compile it and link curl + OpenSSL.
3. **falco_outputs.cpp**: The http output class is guarded by `!defined(MINIMAL_BUILD)`, which bundles it with gRPC/webserver code. Patch adds a separate `#if defined(HAS_HTTP_OUTPUT) && defined(MINIMAL_BUILD)` guard to enable http output without gRPC.

**Design choice**: `MINIMAL_BUILD=ON` + `HAS_HTTP_OUTPUT` preprocessor define. This avoids pulling in gRPC, protobuf, c-ares, cpp-httplib, and the webserver — only curl-based http output is enabled. Rejected alternative: `MINIMAL_BUILD=OFF` would activate all non-minimal code paths (gRPC, webserver, metrics) via preprocessor guards in `start_webserver.cpp`, `start_grpc_server.cpp`, and `falco_outputs.cpp`, requiring all their dependencies.

#### Bundled vs system dependencies

Native macOS builds use **system libraries** for OpenSSL, curl, and zlib:
- `USE_BUNDLED_OPENSSL=OFF` with `OPENSSL_ROOT_DIR` pointing to Homebrew
- `USE_BUNDLED_CURL=OFF` (macOS ships curl)
- `USE_BUNDLED_ZLIB=OFF` (macOS ships zlib)

**Why not bundle everything**: Falco's bundled OpenSSL, curl, and zlib use autotools (`./config`, `./configure`) as ExternalProject builds. These autotools scripts do not respect CMake's `CMAKE_OSX_ARCHITECTURES`, causing architecture mismatch errors on macOS (e.g., `archive member 'adler32.o' not a mach-o file`, `invalid control bits in './libcrypto.a'`). System libraries avoid this entirely.

All other bundled dependencies (TBB, nlohmann-json, jsoncpp, re2, valijson, cxxopts) are CMake-based and build correctly on macOS.

#### Cross-compilation (x86_64 on Apple Silicon)

Cross-compilation uses **Rosetta + x86_64 Homebrew** at `/usr/local`:

```
arch -x86_64 /usr/local/bin/cmake -B build-x86_64 -S . [flags]
arch -x86_64 /usr/local/bin/cmake --build build-x86_64 --target falco
```

Both `arch -x86_64` (Rosetta) AND `CFLAGS="-arch x86_64"` are required:
- `arch -x86_64` makes autotools scripts detect x86_64 via `uname -m` (OpenSSL's `./config` uses this to select `darwin64-x86_64-cc` vs `darwin64-arm64-cc`)
- `CFLAGS="-arch x86_64"` forces Apple's universal compiler to produce x86_64 code (without it, the compiler picks its native arm64 slice)

**Rejected alternatives**:
- **`CMAKE_OSX_ARCHITECTURES` alone**: CMake ExternalProject sub-builds (jsoncpp, TBB, re2) spawn separate cmake processes that ignore the parent's `CMAKE_OSX_ARCHITECTURES`. Empirically verified: `lipo -info` on built jsoncpp showed arm64 despite x86_64 target.
- **`CFLAGS="-arch x86_64"` without Rosetta**: Environment CFLAGS don't propagate to all ExternalProject sub-builds. OpenSSL's `./config` still detects arm64 via `uname -m` and selects ARM assembly, causing `"unsupported ARM architecture"` errors.
- **`MACHINE=x86_64` env var**: OpenSSL's `./config` on macOS ignores the `MACHINE` environment variable for platform detection.
- **Native cmake cross-compilation**: Even with toolchain files, ExternalProject sub-builds don't inherit toolchain settings.
- **Bundling autotools deps for cross-compilation**: zlib and curl autotools builds produce test programs that can't link cross-arch. OpenSSL selects wrong assembly. Not viable without patching each dependency.

#### Universal binary

`make macos-universal` produces a fat arm64+x86_64 package:
1. Rust components cross-compile natively (`cargo build --target x86_64-apple-darwin` works on ARM without Rosetta)
2. Falco arm64 builds natively with system libs
3. Falco x86_64 builds under Rosetta with x86_64 Homebrew
4. `lipo -create` combines each binary pair into a universal fat binary

Prerequisites: Rosetta, x86_64 Homebrew at `/usr/local` with cmake and openssl@3.

### macOS: service management (launchd)

macOS uses launchd instead of systemd. Key differences:

- **Plist**: `~/Library/LaunchAgents/dev.falcosecurity.coding-agents-kit.plist` (label uses `dev.falcosecurity` — the Falco project's registered domain)
- **Hook lifecycle**: launchd has no `ExecStartPost`/`ExecStopPost` equivalent. A wrapper script (`coding-agents-kit-launcher.sh`) runs `ctl hook add` before Falco and uses `trap EXIT TERM INT` to run `ctl hook remove` on shutdown. Falco runs in the foreground (not `exec`) so the trap fires.
- **ctl tool**: Platform-specific via `#[cfg(target_os)]` compile-time branching. Same commands on both platforms (`start/stop/enable/disable/status`), different implementations (systemctl vs launchctl).
- **Plugin library**: `.dylib` on macOS (vs `.so` on Linux). The macOS packager transforms the plugin config via `sed`.

### macOS: `coding-agents-kit-ctl` service commands

| Command | Linux (systemctl) | macOS (launchctl) |
|---------|-------------------|-------------------|
| `start` | `systemctl --user start` | `launchctl load <plist>` |
| `stop` | `systemctl --user stop` | `launchctl unload <plist>` |
| `enable` | `systemctl --user enable` | `launchctl load <plist>` (RunAtLoad in plist) |
| `disable` | `systemctl --user disable` | `launchctl unload -w <plist>` |
| `status` | `systemctl --user status` | `launchctl list <label>` |

The macOS implementation includes `is_service_loaded()` for idempotent start/stop.

## Technology Stack

- **Falco 0.43** — rule engine, running in `nodriver` mode (no kernel instrumentation)
- **Rust** — interceptor and plugin (using `falco_plugin` crate v0.5.0)
- **Platforms** — Linux (official Falco builds), macOS (Falco built from source with http_output patch), Windows (Falco built from source with http_output patch, system curl via vcpkg)

## Build & Development

### Building

```bash
make build                  # Build all components for the native architecture
make build-interceptor      # Interceptor only
make build-plugin           # Plugin only
make build-ctl              # CTL tool only
```

Requires latest stable Rust (the falco_plugin SDK tracks latest stable as MSRV).

### Tests

```bash
make test                   # Run all tests
make test-interceptor       # Interceptor unit tests (mock broker, no Falco needed)
make test-e2e               # E2E tests (requires Falco in PATH, plugin, and interceptor built)
```

On Linux, use `make download-falco-linux` to download pre-built Falco binaries and `make falco-linux-bin-dir` to get the binary path. On macOS, use `make falco-macos` to build from source.

### Packaging

```bash
# Linux (downloads pre-built Falco)
make linux-x86_64
make linux-aarch64

# macOS (builds Falco from source, requires cmake + Homebrew OpenSSL)
make macos-aarch64          # Apple Silicon
make macos-x86_64           # Intel (must run on Intel Mac)
make macos-universal        # Fat binary (requires Rosetta + x86_64 Homebrew)
make falco-macos            # Build only Falco (convenience target)
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CODING_AGENTS_KIT_SOCKET` | `~/.coding-agents-kit/run/broker.sock` | Broker Unix socket path |
| `CODING_AGENTS_KIT_TIMEOUT_MS` | `5000` | Socket read timeout in milliseconds |

## Code Style

### License headers

All source files must use the falcosecurity license header style:

**C/C++ files (.c, .h):**
```c
// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) <year> The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
```

**Rust files (.rs):** No per-file license headers (Rust ecosystem convention). Licensing is declared in `Cargo.toml` and the top-level `LICENSE` file.

The year must be the most recent year the file was modified. Use `The Falco Authors` as copyright holder.
