# Windows Build Prerequisites

This document lists the tools and dependencies required to build coding-agents-kit on Windows.

## Required Software

### Rust Toolchain

Install via [rustup](https://rustup.rs/):

```powershell
# Download and run the installer (ARM64)
curl -o rustup-init.exe https://static.rust-lang.org/rustup/dist/aarch64-pc-windows-msvc/rustup-init.exe
.\rustup-init.exe -y

# For x86_64 machines, use:
# curl -o rustup-init.exe https://win.rustup.rs/x86_64
```

After installation, restart your shell or add `%USERPROFILE%\.cargo\bin` to PATH.

Verify: `rustc --version` (requires 1.80+)

### Visual Studio Build Tools

Required for compiling Rust crates with the MSVC toolchain and for building Falco from source.

Install [Visual Studio 2022+](https://visualstudio.microsoft.com/) (Community edition is free) with these workloads:
- **Desktop development with C++**
  - MSVC v143+ build tools
  - Windows SDK (10.0.26100.0 or later)
  - C++ CMake tools for Windows

Verify: Open "Developer Command Prompt for VS" and run `cl` — it should print the compiler version.

### CMake

Required for building Falco from source. Included with Visual Studio C++ CMake tools, or install standalone from [cmake.org](https://cmake.org/download/).

Verify: `cmake --version` (requires 3.24+)

### Git

Install [Git for Windows](https://git-scm.com/download/win).

Verify: `git --version`

### WiX Toolset v4

Required for building the MSI installer.

Install via .NET tool:

```powershell
dotnet tool install --global wix
```

Or download from [wixtoolset.org](https://wixtoolset.org/).

Verify: `wix --version`

## Optional Software

### Python 3

Required only for running the mock broker in interceptor tests.

Install from [python.org](https://www.python.org/downloads/) or via `winget install Python.Python.3`.

Verify: `python --version`

## Build Commands

```powershell
# Build all Rust components
cargo build --release

# Build Falco from source
powershell -File installers\windows\build-falco.ps1

# Build MSI installer
powershell -File installers\windows\package.ps1 -Version 0.1.0
```

## Architecture Support

| Architecture | Status |
|-------------|--------|
| x86_64 (AMD64) | Supported |
| aarch64 (ARM64) | Supported (native build on ARM64 Windows) |

## Known Caveats

- **Git Bash PATH**: When running PowerShell build scripts from Git Bash, `C:\Windows\System32` must appear before Git's `/usr/bin` in PATH to ensure Windows native `tar.exe` is used instead of GNU tar (which misinterprets `C:` as a remote host). The build scripts handle this automatically.
- **Falco patches**: Falco source patches must be normalized from CRLF to LF before `git apply`. The build scripts handle this automatically.
