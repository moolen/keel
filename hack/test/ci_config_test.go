package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCIWorkflowExistsAndCoversSupportedChecks(t *testing.T) {
	repoRoot := findRepoRoot(t)

	body, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci workflow: %v", err)
	}

	text := string(body)
	for _, want := range []string{
		"go test ./...",
		"cd guest && go test ./...",
		"go build ./cmd/keel",
		"cd guest && go build",
		"golangci-lint",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("ci workflow missing %q", want)
		}
	}
}

func TestGolangCILintConfigExists(t *testing.T) {
	repoRoot := findRepoRoot(t)

	body, err := os.ReadFile(filepath.Join(repoRoot, ".golangci.yml"))
	if err != nil {
		t.Fatalf("read golangci config: %v", err)
	}

	text := string(body)
	for _, want := range []string{
		"version: \"2\"",
		"govet",
		"staticcheck",
		"unused",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("golangci config missing %q", want)
		}
	}
}
