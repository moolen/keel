package test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

type e2eSuite struct {
	repoRoot      string
	imageCacheDir string
	artifacts     builtArtifacts
}

type e2eProject struct {
	suite    *e2eSuite
	dir      string
	home     string
	cacheDir string
	kernel   string
	fixtures e2eFixtures
}

type e2eFixtures struct {
	Hello       string
	Existing    string
	DoNotDelete string
	SourceDir   string
	NodeDir     string
	PythonDir   string
}

type e2eRunResult struct {
	Stdout   string
	Stderr   string
	Combined string
	ExitCode int
	Err      error
}

func newE2ESuite(t *testing.T) *e2eSuite {
	t.Helper()
	requireE2EPrerequisites(t)
	repoRoot := findRepoRoot(t)
	imageCacheDir := e2eImageCacheDir(t)
	return &e2eSuite{
		repoRoot:      repoRoot,
		imageCacheDir: imageCacheDir,
		artifacts:     buildArtifacts(t, repoRoot),
	}
}

func e2eImageCacheDir(t *testing.T) string {
	t.Helper()
	if path := strings.TrimSpace(os.Getenv("KEEL_E2E_IMAGE_CACHE_DIR")); path != "" {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cacheRoot, "keel", "e2e-images")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func (s *e2eSuite) newProject(t *testing.T) *e2eProject {
	t.Helper()

	projectDir := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.MkdirAll(s.imageCacheDir, 0o755); err != nil {
		t.Fatal(err)
	}

	project := &e2eProject{
		suite:    s,
		dir:      projectDir,
		home:     home,
		cacheDir: s.imageCacheDir,
		kernel:   hostKernelPath(),
	}
	project.fixtures = writeE2EFixtures(t, projectDir)
	return project
}

func hostKernelPath() string {
	path := strings.TrimSpace(os.Getenv("KEEL_E2E_KERNEL_PATH"))
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func writeE2EFixtures(t *testing.T, projectDir string) e2eFixtures {
	t.Helper()

	fixtures := e2eFixtures{
		Hello:       filepath.Join(projectDir, "hello.txt"),
		Existing:    filepath.Join(projectDir, "existing.txt"),
		DoNotDelete: filepath.Join(projectDir, "do-not-delete.txt"),
		SourceDir:   filepath.Join(projectDir, "src"),
		NodeDir:     filepath.Join(projectDir, "docker-node"),
		PythonDir:   filepath.Join(projectDir, "docker-python"),
	}

	writeTextFile(t, fixtures.Hello, "hello from host\n")
	writeTextFile(t, fixtures.Existing, "original content\n")
	writeTextFile(t, fixtures.DoNotDelete, "keep me\n")
	writeTextFile(t, filepath.Join(fixtures.SourceDir, "main.go"), `package main

import "fmt"

func main() {
	fmt.Println("hello from go")
}
`)
	writeTextFile(t, filepath.Join(fixtures.NodeDir, "Dockerfile"), `FROM quay.io/libpod/alpine:latest
WORKDIR /app
COPY server.sh .
EXPOSE 3000
CMD ["sh", "server.sh"]
`)
	writeTextFile(t, filepath.Join(fixtures.NodeDir, "server.sh"), `while true; do
  printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16\r\n\r\nhello from node\n' | nc -l -p 3000
done
`)
	writeTextFile(t, filepath.Join(fixtures.PythonDir, "Dockerfile"), `FROM quay.io/libpod/alpine:latest
WORKDIR /app
COPY server.sh .
EXPOSE 5000
CMD ["sh", "server.sh"]
`)
	writeTextFile(t, filepath.Join(fixtures.PythonDir, "server.sh"), `while true; do
  printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 18\r\n\r\nhello from python\n' | nc -l -p 5000
done
`)
	return fixtures
}

func writeTextFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (p *e2eProject) writeConfig(t *testing.T, imageRef, body string) {
	t.Helper()

	if strings.TrimSpace(imageRef) == "" {
		imageRef = "ubuntu:24.04"
	}
	var config strings.Builder
	config.WriteString("image: " + imageRef + "\n")
	config.WriteString("image_cache_dir: " + p.cacheDir + "\n")
	if p.kernel != "" {
		config.WriteString("kernel:\n")
		config.WriteString("  path: " + p.kernel + "\n")
	}
	if trimmed := strings.TrimSpace(body); trimmed != "" {
		config.WriteString(trimmed)
		config.WriteString("\n")
	}
	writeTextFile(t, filepath.Join(p.dir, "keel.yaml"), config.String())
}

func (p *e2eProject) run(t *testing.T, stdin string, args ...string) e2eRunResult {
	t.Helper()

	cmd := exec.CommandContext(context.Background(), p.suite.artifacts.keelPath, args...)
	cmd.Dir = p.dir
	cmd.Env = p.env()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return e2eRunResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Combined: stdout.String() + stderr.String(),
		ExitCode: exitCode(err),
		Err:      err,
	}
}

func (p *e2eProject) runWithSignal(t *testing.T, after time.Duration, signal os.Signal, args ...string) e2eRunResult {
	t.Helper()

	cmd := exec.CommandContext(context.Background(), p.suite.artifacts.keelPath, args...)
	cmd.Dir = p.dir
	cmd.Env = p.env()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return e2eRunResult{Err: err, ExitCode: exitCode(err)}
	}
	time.Sleep(after)
	if cmd.Process != nil {
		_ = cmd.Process.Signal(signal)
	}
	err := cmd.Wait()
	return e2eRunResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Combined: stdout.String() + stderr.String(),
		ExitCode: exitCode(err),
		Err:      err,
	}
}

func (p *e2eProject) runPTY(t *testing.T, input string, args ...string) e2eRunResult {
	t.Helper()

	cmd := exec.CommandContext(context.Background(), p.suite.artifacts.keelPath, args...)
	cmd.Dir = p.dir
	cmd.Env = p.env()

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = ptmx.Close()
	}()

	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&output, ptmx)
		close(done)
	}()

	time.Sleep(3 * time.Second)
	if _, err := io.WriteString(ptmx, input); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	_ = ptmx.Close()
	<-done

	text := output.String()
	return e2eRunResult{
		Stdout:   text,
		Combined: text,
		ExitCode: exitCode(err),
		Err:      err,
	}
}

func (p *e2eProject) env() []string {
	return append(os.Environ(),
		"HOME="+p.home,
		"XDG_CONFIG_HOME="+filepath.Join(p.home, ".config"),
		"XDG_DATA_HOME="+filepath.Join(p.home, ".local", "share"),
	)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func (r e2eRunResult) requireSuccess(t *testing.T) {
	t.Helper()
	if r.Err != nil {
		t.Fatalf("command failed with exit=%d\nstdout:\n%s\nstderr:\n%s", r.ExitCode, r.Stdout, r.Stderr)
	}
}

func (r e2eRunResult) requireFailure(t *testing.T) {
	t.Helper()
	if r.Err == nil {
		t.Fatalf("command unexpectedly succeeded\nstdout:\n%s\nstderr:\n%s", r.Stdout, r.Stderr)
	}
}

func requireContainsAll(t *testing.T, text string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
}

func requireNotContains(t *testing.T, text string, unwanted string) {
	t.Helper()
	if strings.Contains(text, unwanted) {
		t.Fatalf("unexpected %q in output:\n%s", unwanted, text)
	}
}

func requireFileContains(t *testing.T, path string, wants ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	requireContainsAll(t, string(data), wants...)
}

func requireFileMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be missing, stat err=%v", path, err)
	}
}

func bash(command string) []string {
	return []string{"--", "bash", "-lc", wrapGuestCommand(command)}
}

func sh(command string) []string {
	return []string{"--", "sh", "-lc", wrapGuestCommand(command)}
}

func yamlBlock(lines ...string) string {
	return strings.Join(lines, "\n")
}

func wrapGuestCommand(command string) string {
	return "(\n" + command + "\n)\nrc=$?\nsleep 2\nexit $rc\n"
}
