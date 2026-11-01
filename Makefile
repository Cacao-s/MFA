# MFA — Authy-style TOTP authenticator for Android, iOS, macOS and Windows.
#
#   make help     list targets
#
# The core (crates/mfa-core) builds and tests with nothing but a Rust
# toolchain. The platform UIs live in apple/, android/ and windows/ and each
# needs its own SDK, so they are built by the scripts rather than from here
# (temp/spec.md §2); names follow ~/git/dev_docs/project-conventions/SKILL.md.

SHELL   := /bin/bash
OUT     := build

CARGO    ?= cargo
FEATURES ?= --all-features

# The FFI library, whose name differs per platform.
LIB_EXT  := $(shell [ "$$(uname)" = "Darwin" ] && echo dylib || echo so)
FFI_LIB  := target/debug/libmfa_ffi.$(LIB_EXT)

.DEFAULT_GOAL := help
.PHONY: help setup build run server bindings test lint fmt fmt-check check fuzz fixtures clean

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Install toolchain components and fetch dependencies
	rustup component add rustfmt clippy
	$(CARGO) fetch

build: ## Build everything
	$(CARGO) build --workspace $(FEATURES)

run: ## Run the app
	@echo "Nothing here draws a window on this machine. The UI is native per"
	@echo "platform and each one builds with its own toolchain:"
	@echo
	@echo "  apple/    SwiftUI, macOS + iOS   ./scripts/build-apple.sh   (Xcode)"
	@echo "  android/  Compose                ./scripts/build-android.sh (NDK)"
	@echo "  windows/  WinUI 3                windows/MFA.sln            (MSBuild)"
	@echo
	@echo "Each directory has a README with the build steps. The step-0 spike"
	@echo "in spike/ is still outstanding and needs real devices."
	@echo
	@echo "To exercise the core instead:   make test"
	@exit 1

server: ## Run the self-hosted sync server locally
	@test -n "$$MFA_SYNC_TOKEN" || { \
		echo "Set MFA_SYNC_TOKEN first, e.g.:"; \
		echo "  export MFA_SYNC_TOKEN=\"\$$(openssl rand -hex 32)\""; \
		exit 1; }
	$(CARGO) run --release -p mfa-sync-server

bindings: ## Generate the Swift and Kotlin bindings for the core
	$(CARGO) build -p mfa-ffi --lib $(FEATURES)
	$(CARGO) run -q -p mfa-ffi --bin uniffi-bindgen -- generate \
		--library $(FFI_LIB) --language swift  --out-dir bindings/swift
	$(CARGO) run -q -p mfa-ffi --bin uniffi-bindgen -- generate \
		--library $(FFI_LIB) --language kotlin --out-dir bindings/kotlin
	@echo
	@echo "bindings/swift/   and bindings/kotlin/ are generated; do not edit them."
	@echo "For a packaged build:  ./scripts/build-apple.sh  or  ./scripts/build-android.sh"

test: ## Run the test suite
	$(CARGO) test --workspace $(FEATURES)

lint: ## Clippy, warnings as errors
	$(CARGO) clippy --workspace --all-targets $(FEATURES) -- -D warnings

fmt: ## Format the source
	$(CARGO) fmt --all

fmt-check: ## Check formatting without changing anything
	$(CARGO) fmt --all --check

check: fmt-check lint test ## Everything CI will check

fuzz: ## Fuzz one parser, e.g. make fuzz TARGET=otpauth_uri SECONDS=300
	@command -v cargo-fuzz >/dev/null || { \
		echo "cargo-fuzz is not installed:"; \
		echo "  cargo install cargo-fuzz"; \
		exit 1; }
	@test -n "$(TARGET)" || { \
		echo "Pick a target:"; \
		cd fuzz && cargo +nightly fuzz list | sed 's/^/  /'; \
		echo; \
		echo "  make fuzz TARGET=<name> [SECONDS=60]"; \
		exit 1; }
	cd fuzz && cargo +nightly fuzz run $(TARGET) -- -max_total_time=$(or $(SECONDS),60)

fixtures: ## Regenerate test fixtures from the reference scripts
	python3 -I tools/ga_encode.py
	python3 -I tools/totp_ref.py

clean: ## Remove build output
	$(CARGO) clean
	rm -rf $(OUT)
