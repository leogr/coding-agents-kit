# Windows Build & Installation Guide

## Architecture

### Platform

Builds target the native architecture of the machine. The build scripts auto-detect x86_64 or ARM64 and compile accordingly.

### Pipeline

The Windows port uses the same Falco plugin architecture as Linux/macOS:

```
Claude Code
    │  PreToolUse hook
    ▼
claude-interceptor.exe ──Unix socket──▶ Plugin broker (in Falco)
                                              │
                                              ▼
                                       Falco rule engine
                                              │
                                         ┌────┴────┐
                                    Linux/macOS   Windows
                                         │         │
                                   http_output   stdout
                                         │         │
                                         ▼         ▼
                                   Plugin HTTP  stdout-forwarder.exe
                                    server          │
                                         ▲         POST
                                         │         │
                                         └────┬────┘
                                              ▼
                                       Verdict resolution
                                              │
                                              ▼
                                   Response to interceptor
```

| Component | Linux/macOS | Windows |
|-----------|------------|---------|
| Interceptor → broker | Unix domain socket | Unix domain socket (via `uds_windows` crate) |
| Broker | Embedded in plugin | Embedded in plugin |
| Plugin | .so / .dylib loaded by Falco | .dll loaded by Falco |
| Alert delivery | Falco `http_output` (curl) → plugin HTTP server | Falco stdout → `stdout-forwarder` → plugin HTTP server |
| Processes | 1 (Falco) | 2 (Falco + stdout-forwarder) |

### Why the stdout-forwarder is needed

On Linux/macOS, Falco delivers alerts to the plugin's HTTP server using its built-in `http_output`, which uses libcurl to POST to `http://127.0.0.1:<port>`. This is intra-process communication — both Falco and the plugin run in the same process.

On Windows, `http_output` compiles successfully (with system OpenSSL + vcpkg curl) and Falco initializes it without errors. However, **curl silently fails to deliver alerts to localhost**. The root cause is likely curl's interaction with Windows SChannel and/or proxy detection — even for plain HTTP to 127.0.0.1, curl on Windows performs DNS resolution, proxy detection, and SChannel initialization, any of which can hang or fail silently.

The `stdout-forwarder` is a tiny (177KB) Rust binary that bypasses curl entirely. It reads JSON lines from Falco's stdout pipe and POSTs each to the plugin's HTTP server using raw TCP sockets — no curl, no TLS stack, no proxy detection:

```
falco.exe -U -c config.yaml | stdout-forwarder.exe http://127.0.0.1:2802
```

This approach is reliable because:
- Raw TCP to localhost is the simplest possible network operation
- The pipe keeps Falco's stdout flowing (prevents output thread deadlock)
- The forwarder is stateless — each alert is an independent HTTP POST
- No external dependencies (pure Rust, standard library only)

> **Note**: The `http_output` patch (`falco-windows-http-output.patch`) and build support are maintained in the repo. If the curl/localhost issue is resolved in the future (or on native x64 machines where curl may behave differently), `http_output` can replace the forwarder for full parity with Linux/macOS. Both can coexist without conflicts.

## Prerequisites

Install the following in order. All commands should be run from PowerShell.

### 1. Visual Studio Build Tools

Install [Visual Studio 2022+](https://visualstudio.microsoft.com/) (Community is free) with:
- **Desktop development with C++** workload
  - MSVC v143+ build tools
  - Windows SDK (10.0 or later)
  - C++ CMake tools for Windows

Verify:
```powershell
# Open "Developer Command Prompt for VS" and run:
cl
cmake --version   # requires 3.24+
```

### 2. Git

Install [Git for Windows](https://git-scm.com/download/win).

```powershell
git --version
```

### 3. Rust

```powershell
Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile rustup-init.exe
.\rustup-init.exe -y
# Restart your shell, then:
rustc --version    # requires 1.80+
cargo --version

# Add x64 target (needed if building on ARM64 Windows)
rustup target add x86_64-pc-windows-msvc
```

### 4. .NET Runtime + WiX Toolset (for MSI packaging)

```powershell
winget install Microsoft.DotNet.Runtime.9 --accept-package-agreements --accept-source-agreements
dotnet tool install --global wix
wix --version
```

## Building

### Quick Build (all components + MSI)

```powershell
# From the repository root:
powershell -File installers\windows\package.ps1 -Version 0.1.0
```

This single command:
1. Compiles all Rust crates for x64 (interceptor, plugin DLL, ctl, stdout-forwarder)
2. Clones and builds Falco 0.43.0 from source with `http_output` (~10 min, cached)
3. Patches `falco.exe` plugin search path
4. Stages all files and produces the MSI installer

Output: `build/out/coding-agents-kit-0.1.0-windows-x64.msi`

### Step-by-Step Build

```powershell
# 1. Build Rust crates (targets x64)
cd hooks\claude-code && cargo build --release --target x86_64-pc-windows-msvc && cd ..\..
cd plugins\coding-agent-plugin && cargo build --release --target x86_64-pc-windows-msvc && cd ..\..
cd tools\coding-agents-kit-ctl && cargo build --release --target x86_64-pc-windows-msvc && cd ..\..
cd tools\stdout-forwarder && cargo build --release --target x86_64-pc-windows-msvc && cd ..\..

# 2. Build Falco from source (~10 minutes first time, cached after)
powershell -File installers\windows\build-falco.ps1 -Arch x64

# 3. Package MSI (uses pre-built components)
powershell -File installers\windows\package.ps1 -Version 0.1.0 -SkipRustBuild -SkipFalcoBuild
```

### Build Options

| Flag | Description |
|------|-------------|
| `-Version 0.1.0` | Package version (semantic versioning) |
| `-Arch x64` | Target architecture (default: x64) |
| `-SkipRustBuild` | Skip Rust compilation (use pre-built binaries) |
| `-SkipFalcoBuild` | Skip Falco build (use cached build) |
| `-FalcoExe <path>` | Use a specific pre-built `falco.exe` |

## Installing

```powershell
# Install (deploys files + runs postinstall setup)
powershell -File build\out\Install-CodingAgentsKit.ps1

# Or manual MSI + postinstall:
msiexec /i build\out\coding-agents-kit-0.1.0-windows-x64.msi /quiet
powershell -File "$env:LOCALAPPDATA\coding-agents-kit\scripts\postinstall.ps1"
```

The installer:
- Deploys binaries, plugin DLL, rules, and scripts to `%LOCALAPPDATA%\coding-agents-kit\`
- Generates Falco configuration with resolved Windows paths
- Registers the Claude Code interceptor hook
- Sets up auto-start via Registry Run key

### Uninstalling

Via Apps & Features (Settings → Apps), or:

```powershell
powershell -File build\out\Uninstall-CodingAgentsKit.ps1
```

## Running Tests

```powershell
# Interceptor tests (17 test cases, no Falco needed)
powershell -File tests\test_interceptor_windows.ps1

# End-to-end tests (requires built Falco + plugin)
powershell -File tests\test_e2e_windows.ps1
```

## Directory Layout (installed)

```
%LOCALAPPDATA%\coding-agents-kit\
├── bin\
│   ├── falco.exe                          # Falco rule engine (x64)
│   ├── claude-interceptor.exe             # Claude Code hook
│   ├── coding-agents-kit-ctl.exe          # Service management CLI
│   └── coding-agents-kit-launcher.ps1     # Service launcher
├── share\
│   └── coding_agent_plugin.dll            # Falco plugin (source + extract)
├── config\
│   ├── falco.yaml                         # Base Falco config
│   └── falco.coding_agents_plugin.yaml    # Plugin + rules config
├── rules\
│   ├── default\coding_agents_rules.yaml   # Default security rules
│   ├── user\                              # Custom user rules (preserved on upgrade)
│   └── seen.yaml                          # Catch-all rule (required)
├── scripts\
│   ├── postinstall.ps1                    # Post-install setup
│   └── uninstall.ps1                      # Pre-uninstall cleanup
├── run\                                   # Runtime state
└── log\                                   # Falco log files
```

## Known Caveats

- **Git Bash PATH shadowing**: Git Bash's `/usr/bin/tar` misinterprets Windows paths with `C:` as a remote host. The build scripts prepend `C:\Windows\System32` to PATH so Windows native `tar.exe` is used. If running build scripts manually from Git Bash, use: `powershell -File <script>`.

- **Falco patches**: Patch files must be normalized from CRLF to LF before `git apply`. The `build-falco.ps1` script handles this automatically.

- **Falco launched from Git Bash**: Falco may segfault when launched directly from Git Bash due to stdin/stdout handling differences. Always launch via PowerShell or `cmd.exe`. The test scripts and launcher handle this correctly.

- **Path separators in rules**: The plugin normalizes all `real_file_path` and `real_cwd` fields to forward slashes (`C:/Users/...`), so Falco rules should use forward slashes for `startswith` and `contains` comparisons.
