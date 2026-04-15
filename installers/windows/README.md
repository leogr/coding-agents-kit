# Windows Build & Installation Guide

## Architecture

### Platform

Builds target the native architecture of the machine. The build scripts auto-detect x86_64 or ARM64 and compile accordingly.

### Pipeline

The Windows port uses the same Falco plugin architecture as Linux/macOS. Alert delivery uses Falco's native `http_output` on all platforms:

```
Claude Code
    │  PreToolUse hook
    ▼
claude-interceptor.exe ──Unix socket──▶ Plugin broker (in Falco)
                                              │
                                              ▼
                                       Falco rule engine
                                              │
                                              ▼
                                       http_output (curl)
                                              │
                                              ▼
                                       Plugin HTTP server
                                              │
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
| Alert delivery | Falco `http_output` (curl) | Falco `http_output` (curl, patched in) |
| Processes | 1 (Falco) | 1 (Falco) |

### http_output on Windows

Falco's upstream build excludes `http_output` on Windows (CMake and preprocessor guards). The `falco-windows-http-output.patch` enables it using the same `HAS_HTTP_OUTPUT` pattern as the macOS patch. System curl is provided via vcpkg with SChannel backend (no OpenSSL dependency).

A second patch (`falco-windows-curl-noproxy.patch`) handles two SChannel-specific curl limitations:

1. **NOPROXY**: Adds `CURLOPT_NOPROXY="*"` to bypass system/environment proxy settings for localhost alert delivery. Tolerates `CURLE_NOT_BUILT_IN` because the SChannel curl backend may omit proxy support — if proxy support is absent there is no proxy to bypass anyway.

2. **CA path**: Wraps the CA certificate path/bundle options in a Windows-specific block that tolerates `CURLE_NOT_BUILT_IN`. SChannel uses the Windows Certificate Store automatically and does not support `CURLOPT_CAPATH` / `CURLOPT_CAINFO`. The original `CHECK_RES` macro would propagate this error and prevent `http_output` from initializing. For plain HTTP delivery to localhost no CA verification is needed regardless.

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

### 4. vcpkg + curl

vcpkg provides the system curl library used by Falco's `http_output`.

```powershell
git clone https://github.com/microsoft/vcpkg
.\vcpkg\bootstrap-vcpkg.bat
.\vcpkg\vcpkg install curl:x64-windows-static
# Set VCPKG_ROOT so the build script finds it:
$env:VCPKG_ROOT = (Resolve-Path .\vcpkg).Path
```

Note: on recent vcpkg baselines, the `schannel` feature name is not required for this use case. The packaging/build scripts only require `libcurl.lib` to be present under the selected triplet.

### 5. .NET Runtime + WiX Toolset (for MSI packaging)

```powershell
winget install Microsoft.DotNet.Runtime.9 --accept-package-agreements --accept-source-agreements
dotnet tool install --global wix
wix eula accept wix7
wix --version
```

WiX v7 requires explicit OSMF EULA acceptance. Without this, packaging fails with `WIX7015`.

## Building

### Quick Build (all components + MSI)

```powershell
# From the repository root:
powershell -File installers\windows\package.ps1 -Version 0.1.2
```

This single command:
1. Compiles all Rust crates for x64 (interceptor, plugin DLL, ctl)
2. Clones and builds Falco 0.43.0 from source with `http_output` patch (~10 min, cached)
3. Patches `falco.exe` plugin search path
4. Stages all files and produces the MSI installer

Output: `build/out/coding-agents-kit-0.1.2-windows-x64.msi`

### Step-by-Step Build

```powershell
# 1. Build Rust crates (targets x64)
cd hooks\claude-code && cargo build --release --target x86_64-pc-windows-msvc && cd ..\..
cd plugins\coding-agent-plugin && cargo build --release --target x86_64-pc-windows-msvc && cd ..\..
cd tools\coding-agents-kit-ctl && cargo build --release --target x86_64-pc-windows-msvc && cd ..\..

# 2. Build Falco from source (~10 minutes first time, cached after)
powershell -File installers\windows\build-falco.ps1 -Arch x64

# 3. Package MSI (uses pre-built components)
powershell -File installers\windows\package.ps1 -Version 0.1.2 -SkipRustBuild -SkipFalcoBuild
```

### Build Options

| Flag | Description |
|------|-------------|
| `-Version 0.1.2` | Package version (semantic versioning) |
| `-Arch x64` | Target architecture (default: x64) |
| `-SkipRustBuild` | Skip Rust compilation (use pre-built binaries) |
| `-SkipFalcoBuild` | Skip Falco build (use cached build) |
| `-FalcoExe <path>` | Use a specific pre-built `falco.exe` |

## Installing

```powershell
# Install (deploys files + runs postinstall setup deterministically)
powershell -File build\out\Install-CodingAgentsKit.ps1

# Or run MSI directly (shows a standard wizard with acceptance notice)
msiexec /i build\out\coding-agents-kit-0.1.2-windows-x64.msi
```

The installer:
- Deploys binaries, plugin DLL, rules, and scripts to `%LOCALAPPDATA%\coding-agents-kit\`
- Generates Falco configuration with resolved Windows paths
- Registers the Claude Code interceptor hook
- Sets up auto-start via Registry Run key

The MSI wizard now includes an acceptance notice that explains the hook, auto-start, and fail-closed behavior before installation continues.

If the product is already installed, `Install-CodingAgentsKit.ps1` opens the MSI maintenance UI instead of forcing a silent reinstall.

For unattended/silent automation, prefer `Install-CodingAgentsKit.ps1` so post-install tasks are always executed in user context and the script prints a final completion line.

If you run the helper script, it prints a final completion line: `coding-agents-kit installation complete`.

### Uninstalling

**Always use the uninstall helper script** — it runs the cleanup script, removes the Claude Code hook, removes the auto-start registry key, and then removes the MSI-managed files:

```powershell
powershell -File Uninstall-CodingAgentsKit.ps1
```

> **Warning**: Do NOT uninstall via Apps & Features or `msiexec /x` directly. The MSI alone cannot run cleanup scripts (Windows limitation for per-user installs), so the Claude Code hook and auto-start registry key would be left behind, leaving Claude Code in a fail-closed state.

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
│   └── coding_agent.dll            # Falco plugin (source + extract)
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

- **`broker response timeout` / stale pending requests**: if Claude Code tool calls are denied with a broker timeout and Falco logs show `reaping stale pending request`, the alert round-trip is not completing. The most common cause is a misconfigured `http_output.url` in `falco.yaml` (must match the plugin's `http_port`) or an older Falco build without the SChannel curl fix in `falco-windows-curl-noproxy.patch`. Run `coding-agents-kit-ctl health` to confirm the pipeline is healthy after starting the service.

- **ARM64 hosts and Rust/MSVC arch alignment**: on ARM64 Windows, use matching ARM64 toolchain for Rust host (`stable-aarch64-pc-windows-msvc`) and MSVC (`vcvarsall arm64`) when building ARM64 artifacts. Mixed host/target toolchains can fail with unresolved externals at link time.

- **Falco nested CMake generator on ARM64 hosts**: Falco's `falcosecurity-libs` nested configure may choose a Visual Studio generator/platform different from the top-level build if generator/platform are not forwarded explicitly. Keep nested and top-level generator settings aligned to avoid `VCTargetsPath` / platform mismatch errors.

- **Git Bash PATH shadowing**: Git Bash's `/usr/bin/tar` misinterprets Windows paths with `C:` as a remote host. The build scripts prepend `C:\Windows\System32` to PATH so Windows native `tar.exe` is used. If running build scripts manually from Git Bash, use: `powershell -File <script>`.

- **Falco patches**: Patch files must be normalized from CRLF to LF before `git apply`. The `build-falco.ps1` script handles this automatically.

- **Falco launched from Git Bash**: Falco may segfault when launched directly from Git Bash due to stdin/stdout handling differences. Always launch via PowerShell or `cmd.exe`. The test scripts and launcher handle this correctly.

- **Path separators in rules**: The plugin normalizes all `real_file_path` and `real_cwd` fields to forward slashes (`C:/Users/...`), so Falco rules should use forward slashes for `startswith` and `contains` comparisons.
