VERSION := 0.1.0

.PHONY: all linux linux-x86_64 linux-aarch64 macos macos-aarch64 macos-x86_64 macos-universal falco-macos clean help

all: linux

## Build Linux packages for all architectures
linux: linux-x86_64 linux-aarch64

## Build Linux package for x86_64
linux-x86_64:
	bash installers/linux/package.sh --target x86_64

## Build Linux package for aarch64 (requires cross toolchain)
linux-aarch64:
	bash installers/linux/package.sh --target aarch64

## Build macOS package for the native architecture
macos: macos-aarch64

## Build macOS package for Apple Silicon
macos-aarch64:
	bash installers/macos/package.sh --target aarch64

## Build macOS package for Intel (must run on Intel Mac)
macos-x86_64:
	bash installers/macos/package.sh --target x86_64

## Build macOS universal binary package (requires Rosetta + x86_64 Homebrew)
macos-universal:
	bash installers/macos/package.sh --target universal

## Build Falco from source for macOS (required before packaging)
falco-macos:
	bash installers/macos/build-falco.sh

## Remove build artifacts
clean:
	rm -rf build/
	-cd hooks/claude-code && cargo clean
	-cd plugins/coding-agent-plugin && cargo clean
	-cd tools/coding-agents-kit-ctl && cargo clean

## Show available targets
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all             Build Linux packages for all architectures (default)"
	@echo "  linux           Same as all"
	@echo "  linux-x86_64    Build Linux x86_64 package"
	@echo "  linux-aarch64   Build Linux aarch64 package (requires cross toolchain)"
	@echo "  macos           Build macOS package for native architecture"
	@echo "  macos-aarch64   Build macOS Apple Silicon package"
	@echo "  macos-x86_64    Build macOS Intel package (must run on Intel Mac)"
	@echo "  macos-universal Build macOS universal binary (requires Rosetta + x86_64 Homebrew)"
	@echo "  falco-macos     Build Falco from source for macOS"
	@echo "  clean           Remove all build artifacts"
	@echo ""
	@echo "Output:"
	@echo "  build/coding-agents-kit-$(VERSION)-linux-x86_64.tar.gz"
	@echo "  build/coding-agents-kit-$(VERSION)-linux-aarch64.tar.gz"
	@echo "  build/coding-agents-kit-$(VERSION)-darwin-aarch64.tar.gz"
	@echo "  build/coding-agents-kit-$(VERSION)-darwin-x86_64.tar.gz"
	@echo "  build/coding-agents-kit-$(VERSION)-darwin-universal.tar.gz"
