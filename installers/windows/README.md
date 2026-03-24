# Windows Build & Installation Guide

## Architecture

x86_64 (AMD64) builds are the recommended target. They run natively on x86_64 Windows and via emulation on ARM64 Windows 11 — no separate ARM64 build is needed.

## Prerequisites

### Required

| Tool | Version | Purpose | Install |
|------|---------|---------|---------|
| **Rust** | 1.80+ | Compile interceptor, plugin DLL, ctl, forwarder | [rustup.rs](https://rustup.rs/) |
| **Visual Studio** | 2022+ | MSVC compiler, Windows SDK, CMake | [visualstudio.microsoft.com](https://visualstudio.microsoft.com/) |
| **CMake** | 3.24+ | Build Falco from source | Included with VS C++ CMake tools |
| **Git** | any | Clone Falco source, apply patches | [git-scm.com](https://git-scm.com/download/win) |
| **.NET Runtime** | 8.0+ | Required by WiX Toolset | `winget install Microsoft.DotNet.Runtime.9` |
| **WiX Toolset** | v4 | Build MSI installer | `dotnet tool install --global wix` |

### Install Rust

```powershell
# Download and run (works on both x64 and ARM64)
Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile rustup-init.exe
.\rustup-init.exe -y
# Restart your shell, then verify:
rustc --version
cargo --version
```

### Install Visual Studio Build Tools

Install [Visual Studio 2022+](https://visualstudio.microsoft.com/) (Community is free) with:
- **Desktop development with C++** workload
  - MSVC v143+ build tools
  - Windows SDK (10.0 or later)
  - C++ CMake tools for Windows

Verify: open "Developer Command Prompt for VS" and run `cl`.

### Install WiX

```powershell
# .NET runtime (if not installed)
winget install Microsoft.DotNet.Runtime.9

# WiX Toolset v4
dotnet tool install --global wix

# Verify
wix --version
```

## Building

### Quick Build (all components)

```powershell
# From the repository root:
powershell -File installers\windows\package.ps1 -Version 0.1.0
```

This single command:
1. Compiles all Rust crates (interceptor, plugin, ctl, stdout-forwarder)
2. Builds Falco 0.43.0 from source (cached after first build)
3. Patches `falco.exe` plugin search path
4. Stages all files
5. Produces the MSI installer

Output: `build/out/coding-agents-kit-0.1.0-windows-x64.msi`

### Step-by-Step Build

```powershell
# 1. Build Rust crates
cd hooks\claude-code && cargo build --release && cd ..\..
cd plugins\coding-agent-plugin && cargo build --release && cd ..\..
cd tools\coding-agents-kit-ctl && cargo build --release && cd ..\..
cd tools\stdout-forwarder && cargo build --release && cd ..\..

# 2. Build Falco from source (~10 minutes, cached)
powershell -File installers\windows\build-falco.ps1

# 3. Build MSI (uses pre-built components)
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
# Install (deploys files to %LOCALAPPDATA%\coding-agents-kit\)
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

# End-to-end tests (10 test cases, requires built Falco + plugin)
powershell -File tests\test_e2e_windows.ps1
```

## Windows Architecture

The Windows port uses the same Falco plugin architecture as Linux/macOS with two adaptations:

1. **IPC**: TCP on `127.0.0.1:2803` instead of Unix domain sockets (Rust's `std::os::unix::net` is not available on Windows).

2. **Alert delivery**: Falco's `http_output` requires curl, which is not currently enabled in the Windows MINIMAL_BUILD. Curl's bundled autotools build fails on ARM64 Windows; system OpenSSL is available (`winget install ShiningLight.OpenSSL.Dev`) but a matching curl development package has not been tested yet. As a workaround, Falco writes JSON alerts to stdout, and a lightweight `stdout-forwarder` binary pipes each line to the plugin's HTTP server via localhost:

```
falco.exe -U ... | stdout-forwarder.exe http://127.0.0.1:2802
```

> **Future improvement**: Enabling `http_output` natively (by providing system curl libraries or using x64 builds where autotools works) would eliminate the need for the stdout-forwarder. The `falco-windows-http-output.patch` is already prepared for this.

### Directory Layout (installed)

```
%LOCALAPPDATA%\coding-agents-kit\
├── bin\
│   ├── falco.exe                          # Falco rule engine
│   ├── claude-interceptor.exe             # Claude Code hook
│   ├── coding-agents-kit-ctl.exe          # Service management CLI
│   ├── stdout-forwarder.exe               # Alert bridge (stdout → HTTP)
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

- **Git Bash PATH shadowing**: Git Bash's `/usr/bin/tar` misinterprets Windows paths with `C:` as a remote host. The build scripts prepend `C:\Windows\System32` to PATH so Windows native `tar.exe` is used. If running build scripts manually from Git Bash, use the wrapper: `powershell -File <script>`.

- **Falco patches**: Patch files must be normalized from CRLF to LF before `git apply`. The `build-falco.ps1` script handles this automatically.

- **Falco launched from Git Bash**: Falco may segfault when launched directly from Git Bash due to stdin/stdout handling differences. Always launch via PowerShell's `Process::Start` or `cmd.exe`. The test scripts and launcher handle this correctly.

- **Path separators in rules**: The plugin normalizes all `real_file_path` and `real_cwd` fields to forward slashes (`C:/Users/...`), so Falco rules should use forward slashes for `startswith` and `contains` comparisons.
