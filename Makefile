GO ?= go

.PHONY: test lint build guest-agent kernel

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...
	cd guest && golangci-lint run ./...

build:
	$(GO) build ./cmd/keel

guest-agent:
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -o ../dist/keel-agent ./cmd/keel-agent

kernel:
	bash ./hack/kernel/build-kernel.sh
