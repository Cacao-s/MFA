# MFA — Authy-style TOTP authenticator for Android, iOS, macOS and Windows.
#
#   make help     list targets
#
# Build/test targets land once the stack is chosen (docs/spec.md §2);
# names follow ~/git/dev_docs/project-conventions/SKILL.md.

SHELL   := /bin/bash
OUT     := build

.DEFAULT_GOAL := help
.PHONY: help

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
