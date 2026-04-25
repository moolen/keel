package vm

import (
	"strings"
	"testing"

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
	if len(fcCfg.Drives) != 2 {
		t.Fatalf("len(Drives) = %d, want 2", len(fcCfg.Drives))
	}
}
