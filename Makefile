# MFA — Authy-style TOTP authenticator for Android, iOS, macOS and Windows.
#
#   make help     list targets
#
# The core (crates/mfa-core) builds and tests with nothing but a Rust
# toolchain. UI and packaging targets land once the stack is chosen
# (docs/spec.md §2); names follow ~/git/dev_docs/project-conventions/SKILL.md.

SHELL   := /bin/bash
OUT     := build

CARGO    ?= cargo
FEATURES ?= --all-features

.DEFAULT_GOAL := help
.PHONY: help setup build run server test lint fmt fmt-check check fixtures clean

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Install toolchain components and fetch dependencies
	rustup component add rustfmt clippy
	$(CARGO) fetch

build: ## Build everything
	$(CARGO) build --workspace $(FEATURES)

run: ## Run the app
	@echo "There is no app to run yet: this repository holds the"
	@echo "platform-independent core and nothing that draws a window. The UI"
	@echo "layer is blocked on the step-0 spike and the stack choice that"
	@echo "follows it — see spike/README.md."
	@echo
	@echo "To exercise the core instead:   make test"
	@exit 1

server: ## Run the self-hosted sync server locally
	@test -n "$$MFA_SYNC_TOKEN" || { \
		echo "Set MFA_SYNC_TOKEN first, e.g.:"; \
		echo "  export MFA_SYNC_TOKEN=\"\$$(openssl rand -hex 32)\""; \
		exit 1; }
	$(CARGO) run --release -p mfa-sync-server

test: ## Run the test suite
	$(CARGO) test --workspace $(FEATURES)

lint: ## Clippy, warnings as errors
	$(CARGO) clippy --workspace --all-targets $(FEATURES) -- -D warnings

fmt: ## Format the source
	$(CARGO) fmt --all

fmt-check: ## Check formatting without changing anything
	$(CARGO) fmt --all --check

check: fmt-check lint test ## Everything CI will check

fixtures: ## Regenerate test fixtures from the reference scripts
	python3 -I tools/ga_encode.py
	python3 -I tools/totp_ref.py

clean: ## Remove build output
	$(CARGO) clean
	rm -rf $(OUT)
