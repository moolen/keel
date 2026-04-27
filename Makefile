GO ?= go
GOLANGCI_LINT_VERSION ?= v2.11.4

.PHONY: test lint install-lint build guest-agent kernel

test:
	$(GO) test ./...

install-lint:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: install-lint
	golangci-lint run ./...
	cd guest && golangci-lint run ./...

build:
	$(GO) build ./cmd/keel

guest-agent:
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -o ../dist/keel-agent ./cmd/keel-agent

kernel:
	bash ./hack/kernel/build-kernel.sh
