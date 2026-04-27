package vm

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
)

func TestKernelManagerEnsureDownloadsLatestKernel(t *testing.T) {
	destPath := t.TempDir() + "/vmlinux"
	var progress []KernelProgress
	manager := KernelManager{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case strings.Contains(req.URL.String(), "list-type=2"):
				return stringResponse(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-5.10.245</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-6.1.155</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-6.1.155.config</Key></Contents>
</ListBucketResult>`), nil
			case strings.HasSuffix(req.URL.String(), "/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155"):
				return stringResponse("kernel-bytes"), nil
			default:
				t.Fatalf("unexpected URL: %s", req.URL.String())
				return nil, nil
			}
		})},
		FirecrackerVersion: func(context.Context) (string, error) {
			return "Firecracker v1.15.1", nil
		},
		Arch: "x86_64",
		Progress: func(update KernelProgress) {
			progress = append(progress, update)
		},
	}

	gotPath, err := manager.Ensure(context.Background(), destPath)
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if gotPath != destPath {
		t.Fatalf("Ensure() path = %q, want %q", gotPath, destPath)
	}
	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "kernel-bytes" {
		t.Fatalf("kernel data = %q, want kernel-bytes", string(data))
	}
	if len(progress) < 2 {
		t.Fatalf("progress = %#v, want multiple updates", progress)
	}
	if got := progress[0].Phase; got != "downloading kernel" {
		t.Fatalf("progress[0].Phase = %q, want downloading kernel", got)
	}
	if got := progress[len(progress)-1].Current; got != int64(len("kernel-bytes")) {
		t.Fatalf("last progress current = %d, want %d", got, len("kernel-bytes"))
	}
}

func TestKernelManagerRespectsExistingKernel(t *testing.T) {
	destPath := t.TempDir() + "/vmlinux"
	if err := os.WriteFile(destPath, []byte("existing"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	manager := KernelManager{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("unexpected HTTP request: %s", req.URL.String())
			return nil, nil
		})},
	}

	if _, err := manager.Ensure(context.Background(), destPath); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
}

func TestKernelManagerEnsureConfigUsesKernelPathDirectly(t *testing.T) {
	kernelPath := filepath.Join(t.TempDir(), "custom-vmlinux")
	if err := os.WriteFile(kernelPath, []byte("kernel"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	manager := KernelManager{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("unexpected HTTP request: %s", req.URL.String())
			return nil, nil
		})},
	}

	gotPath, err := manager.EnsureConfig(context.Background(), config.KernelConfig{
		Path:   kernelPath,
		Source: "release://latest",
	})
	if err != nil {
		t.Fatalf("EnsureConfig() error = %v", err)
	}
	if gotPath != kernelPath {
		t.Fatalf("EnsureConfig() path = %q, want %q", gotPath, kernelPath)
	}
}

func TestInstalledFirecrackerVersionReturnsInstallHintWhenMissing(t *testing.T) {
	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", originalPath)

	_, err := installedFirecrackerVersion(context.Background())
	if err == nil {
		t.Fatal("installedFirecrackerVersion() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "not installed or not in PATH") {
		t.Fatalf("error = %q, want install hint", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func stringResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
