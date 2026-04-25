package vm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/moolen/keel/internal/config"
)

func TestValidateRequiresKernelAndRootfs(t *testing.T) {
	machine := NewMachine(config.Default(), RuntimeAssets{})

	err := machine.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "kernel") {
		t.Fatalf("Validate() error = %v, want kernel failure", err)
	}
}

func TestBuildConfigUsesRuntimeAssets(t *testing.T) {
	cfg := config.Default()
	cfg.Resources.VCPU = 4
	cfg.Resources.MemoryMB = 3072
	cfg.Workspace.Target = "/workspace"
	cfg.Command = []string{"/bin/sh", "-lc", "echo hi"}

	machine := NewMachine(cfg, RuntimeAssets{
		KernelPath:    "/tmp/vmlinux",
		RootfsPath:    "/tmp/rootfs.ext4",
		WorkspacePath: "/tmp/workspace.ext4",
		SocketPath:    "/tmp/firecracker.sock",
		VSockPath:     "/tmp/firecracker.vsock",
		LogPath:       "/tmp/firecracker.log",
		CID:           52,
	})

	fcCfg, err := machine.BuildConfig()
	if err != nil {
		t.Fatalf("BuildConfig() error = %v", err)
	}
	if got, want := fcCfg.SocketPath, "/tmp/firecracker.sock"; got != want {
		t.Fatalf("SocketPath = %q, want %q", got, want)
	}
	if got, want := *fcCfg.MachineCfg.VcpuCount, int64(4); got != want {
		t.Fatalf("VcpuCount = %d, want %d", got, want)
	}
	if got, want := *fcCfg.MachineCfg.MemSizeMib, int64(3072); got != want {
		t.Fatalf("MemSizeMib = %d, want %d", got, want)
	}
	if !strings.Contains(fcCfg.KernelArgs, "root=/dev/vda") {
		t.Fatalf("KernelArgs missing root device: %q", fcCfg.KernelArgs)
	}
	if !strings.Contains(fcCfg.KernelArgs, "keel.cwd=/workspace") {
		t.Fatalf("KernelArgs missing cwd: %q", fcCfg.KernelArgs)
	}
	command := decodeKernelCommand(t, fcCfg.KernelArgs)
	if len(command) != 3 || command[2] != "echo hi" {
		t.Fatalf("decoded command = %#v", command)
	}
	if len(fcCfg.Drives) != 2 {
		t.Fatalf("len(Drives) = %d, want 2", len(fcCfg.Drives))
	}
}

func TestRunStartsAndWaitsForFirecracker(t *testing.T) {
	assets := createRuntimeAssets(t)
	cfg := config.Default()

	var started bool
	var waited bool
	machine := NewMachine(cfg, assets)
	machine.AttachPTY = func(context.Context, string) error { return nil }
	machine.NewFirecracker = func(_ context.Context, cfg firecracker.Config) (firecrackerMachine, error) {
		if got, want := cfg.SocketPath, assets.SocketPath; got != want {
			t.Fatalf("SocketPath = %q, want %q", got, want)
		}
		return stubFirecrackerMachine{
			start: func(context.Context) error {
				started = true
				return nil
			},
			wait: func(context.Context) error {
				waited = true
				return nil
			},
		}, nil
	}

	if err := machine.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !started || !waited {
		t.Fatalf("started=%v waited=%v, want both true", started, waited)
	}
}

func TestRunRemovesStaleRuntimeSockets(t *testing.T) {
	assets := createRuntimeAssets(t)
	cfg := config.Default()
	for _, path := range []string{assets.SocketPath, assets.VSockPath, assets.LogPath} {
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}

	machine := NewMachine(cfg, assets)
	machine.AttachPTY = func(context.Context, string) error { return nil }
	machine.NewFirecracker = func(_ context.Context, _ firecracker.Config) (firecrackerMachine, error) {
		for _, path := range []string{assets.SocketPath, assets.VSockPath, assets.LogPath} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("expected %q to be removed before launch, stat err=%v", path, err)
			}
		}
		return stubFirecrackerMachine{}, nil
	}

	if err := machine.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func createRuntimeAssets(t *testing.T) RuntimeAssets {
	t.Helper()
	dir := t.TempDir()
	assets := RuntimeAssets{
		KernelPath:    filepath.Join(dir, "vmlinux"),
		RootfsPath:    filepath.Join(dir, "rootfs.ext4"),
		WorkspacePath: filepath.Join(dir, "workspace.ext4"),
		SocketPath:    filepath.Join(dir, "firecracker.sock"),
		VSockPath:     filepath.Join(dir, "firecracker.vsock"),
		LogPath:       filepath.Join(dir, "firecracker.log"),
		CID:           52,
	}
	for _, path := range []string{assets.KernelPath, assets.RootfsPath, assets.WorkspacePath} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}
	return assets
}

type stubFirecrackerMachine struct {
	start func(context.Context) error
	wait  func(context.Context) error
}

func (m stubFirecrackerMachine) Start(ctx context.Context) error {
	if m.start != nil {
		return m.start(ctx)
	}
	return nil
}

func (m stubFirecrackerMachine) Wait(ctx context.Context) error {
	if m.wait != nil {
		return m.wait(ctx)
	}
	return nil
}

func decodeKernelCommand(t *testing.T, kernelArgs string) []string {
	t.Helper()
	for _, field := range strings.Fields(kernelArgs) {
		if !strings.HasPrefix(field, "keel.cmd=") {
			continue
		}
		encoded := strings.TrimPrefix(field, "keel.cmd=")
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("DecodeString() error = %v", err)
		}
		var command []string
		if err := json.Unmarshal(data, &command); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		return command
	}
	t.Fatalf("keel.cmd not found in %q", kernelArgs)
	return nil
}
