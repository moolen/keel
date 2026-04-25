GO ?= /usr/lib/go-1.24/bin/go

.PHONY: test build guest-agent kernel

test:
	$(GO) test ./...

build:
	$(GO) build ./cmd/keel

guest-agent:
	cd guest && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -o ../dist/keel-agent ./cmd/keel-agent

kernel:
	bash ./hack/kernel/build.sh
