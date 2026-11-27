.PHONY: help tidy fmt fix vet get lint test check ensure-golangci-lint bump publish require-clean

# Semver bump kind: make publish [major|minor|patch] (default patch)
# Also accepts typo "minior" → minor.
BUMP := $(word 2,$(MAKECMDGOALS))
ifeq ($(BUMP),)
BUMP := patch
endif
ifeq ($(BUMP),minior)
BUMP := minor
endif

MODULE      := $(shell awk '/^module /{print $$2; exit}' go.mod)
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_INSTALL_URL := https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh
PROXY_HOST  ?= proxy.golang.org
SKIP_CHECK  ?= 0
SKIP_PUSH   ?= 0
SKIP_PROXY  ?= 0
ALLOW_DIRTY ?= 0

help:
	@echo "goauth module Makefile ($(MODULE))"
	@echo ""
	@echo "Quality:"
	@echo "  make tidy | fmt | fix | vet | get | lint | test | check"
	@echo ""
	@echo "Release:"
	@echo "  make bump [major|minor|patch]     # local annotated tag only (default: patch)"
	@echo "  make publish [major|minor|patch]  # check → bump → push tag → go proxy"
	@echo ""
	@echo "Env: SKIP_CHECK=1 SKIP_PUSH=1 SKIP_PROXY=1 ALLOW_DIRTY=1"

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

tidy:
	@echo "==> go mod tidy"
	go mod tidy

fmt:
	@echo "==> go fmt ./..."
	go fmt ./...

fix:
	@echo "==> go fix ./..."
	go fix ./...

vet:
	@echo "==> go vet ./..."
	go vet ./...

get:
	@echo "==> go get ./..."
	go get ./...

test:
	@echo "==> go test ./... (all packages in this module)"
	go test ./... -count=1

ensure-golangci-lint:
	@if ! command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		echo "==> installing golangci-lint into $$(go env GOPATH)/bin"; \
		curl -sSfL "$(GOLANGCI_INSTALL_URL)" | sh -s -- -b "$$(go env GOPATH)/bin"; \
		if ! command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
			echo "golangci-lint installed but not on PATH; add $$(go env GOPATH)/bin to PATH"; \
			exit 1; \
		fi; \
	fi

lint: ensure-golangci-lint
	@echo "==> golangci-lint run"
	$(GOLANGCI_LINT) run

# tidy → fmt → fix → vet → lint → test (used by publish)
check: tidy fmt fix vet lint test
	@echo "==> check: ok"

# ---------------------------------------------------------------------------
# Version / publish
# ---------------------------------------------------------------------------

require-clean:
	@if [ "$(ALLOW_DIRTY)" != "1" ] && [ -n "$$(git status --porcelain)" ]; then \
		echo "ERROR: working tree is dirty; commit/stash first (or ALLOW_DIRTY=1)"; \
		git status --short; \
		exit 1; \
	fi

# Create annotated tag locally: make bump [major|minor|patch]
bump: require-clean
	@case "$(BUMP)" in major|minor|patch) ;; *) \
		echo "Usage: make bump [major|minor|patch]"; exit 1 ;; esac
	@set -e; \
	cur="$$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)"; \
	ver="$${cur#v}"; \
	if ! echo "$$ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "ERROR: current tag '$$cur' is not semver vX.Y.Z"; exit 1; \
	fi; \
	major=$$(echo "$$ver" | cut -d. -f1); \
	minor=$$(echo "$$ver" | cut -d. -f2); \
	patch=$$(echo "$$ver" | cut -d. -f3); \
	case "$(BUMP)" in \
		major) major=$$((major + 1)); minor=0; patch=0 ;; \
		minor) minor=$$((minor + 1)); patch=0 ;; \
		patch) patch=$$((patch + 1)) ;; \
	esac; \
	next="v$${major}.$${minor}.$${patch}"; \
	echo "==> bump $$cur → $$next ($(BUMP))"; \
	if git rev-parse "$$next" >/dev/null 2>&1; then \
		echo "ERROR: tag $$next already exists"; exit 1; \
	fi; \
	git tag -a "$$next" -m "Release $$next"; \
	echo "==> created tag $$next"

# check → bump → push tag → notify Go module proxy
# Usage: make publish [major|minor|patch]
publish:
	@case "$(BUMP)" in major|minor|patch) ;; *) \
		echo "Usage: make publish [major|minor|patch]"; exit 1 ;; esac
	@if [ "$(SKIP_CHECK)" = "1" ]; then \
		echo "==> skip checks (SKIP_CHECK=1)"; \
	else \
		$(MAKE) check; \
	fi
	@$(MAKE) require-clean
	@set -e; \
	cur="$$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)"; \
	ver="$${cur#v}"; \
	if ! echo "$$ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "ERROR: current tag '$$cur' is not semver vX.Y.Z"; exit 1; \
	fi; \
	major=$$(echo "$$ver" | cut -d. -f1); \
	minor=$$(echo "$$ver" | cut -d. -f2); \
	patch=$$(echo "$$ver" | cut -d. -f3); \
	case "$(BUMP)" in \
		major) major=$$((major + 1)); minor=0; patch=0 ;; \
		minor) minor=$$((minor + 1)); patch=0 ;; \
		patch) patch=$$((patch + 1)) ;; \
	esac; \
	next="v$${major}.$${minor}.$${patch}"; \
	echo "==> bump $$cur → $$next ($(BUMP))"; \
	if git rev-parse "$$next" >/dev/null 2>&1; then \
		echo "ERROR: tag $$next already exists"; exit 1; \
	fi; \
	git tag -a "$$next" -m "Release $$next"; \
	echo "==> created tag $$next"; \
	if [ "$(SKIP_PUSH)" = "1" ]; then \
		echo "==> skip push (SKIP_PUSH=1)"; \
	else \
		echo "==> git push origin $$next"; \
		git push origin "$$next"; \
	fi; \
	if [ "$(SKIP_PROXY)" = "1" ]; then \
		echo "==> skip proxy (SKIP_PROXY=1)"; \
	else \
		echo "==> notify $(PROXY_HOST) for $(MODULE)@$$next"; \
		GOPROXY=$(PROXY_HOST) go list -m "$(MODULE)@$$next" \
			|| curl -fsSL "https://$(PROXY_HOST)/$(MODULE)/@v/$$next.info" >/dev/null; \
		echo "==> proxy: https://pkg.go.dev/$(MODULE)@$$next"; \
	fi; \
	echo "==> publish complete: $(MODULE)@$$next"

# Swallow bump words so `make publish minor` does not error as unknown goals.
major minor patch minior:
	@:
