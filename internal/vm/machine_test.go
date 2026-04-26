package vm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
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

func TestBuildHypervisorConfigUsesRuntimeAssets(t *testing.T) {
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

	hvCfg, err := machine.BuildHypervisorConfig()
	if err != nil {
		t.Fatalf("BuildHypervisorConfig() error = %v", err)
	}
	if got, want := hvCfg.SocketPath, "/tmp/firecracker.sock"; got != want {
		t.Fatalf("SocketPath = %q, want %q", got, want)
	}
	if got, want := hvCfg.VCPUs, 4; got != want {
		t.Fatalf("VcpuCount = %d, want %d", got, want)
	}
	if got, want := hvCfg.MemoryMB, 3072; got != want {
		t.Fatalf("MemSizeMib = %d, want %d", got, want)
	}
	if !strings.Contains(hvCfg.KernelArgs, "root=/dev/vda") {
		t.Fatalf("KernelArgs missing root device: %q", hvCfg.KernelArgs)
	}
	if !strings.Contains(hvCfg.KernelArgs, "keel.cwd=/workspace") {
		t.Fatalf("KernelArgs missing cwd: %q", hvCfg.KernelArgs)
	}
	command := decodeKernelCommand(t, hvCfg.KernelArgs)
	if len(command) != 3 || command[2] != "echo hi" {
		t.Fatalf("decoded command = %#v", command)
	}
	if got, want := hvCfg.RootDrive.Path, "/tmp/rootfs.ext4"; got != want {
		t.Fatalf("RootDrive.Path = %q, want %q", got, want)
	}
	if len(hvCfg.ExtraDrives) != 1 {
		t.Fatalf("len(ExtraDrives) = %d, want 1", len(hvCfg.ExtraDrives))
	}
}

func TestBuildHypervisorConfigEncodesFeaturesInKernelArgs(t *testing.T) {
	cfg := config.Default()
	cfg.Features = []config.FeatureConfig{{
		Name: "docker",
		Config: map[string]any{
			"storage_driver": "vfs",
		},
	}}

	machine := NewMachine(cfg, RuntimeAssets{
		KernelPath:    "/tmp/vmlinux",
		RootfsPath:    "/tmp/rootfs.ext4",
		WorkspacePath: "/tmp/workspace.ext4",
		SocketPath:    "/tmp/firecracker.sock",
		VSockPath:     "/tmp/firecracker.vsock",
		LogPath:       "/tmp/firecracker.log",
		CID:           52,
	})

	hvCfg, err := machine.BuildHypervisorConfig()
	if err != nil {
		t.Fatalf("BuildHypervisorConfig() error = %v", err)
	}
	features := decodeKernelFeatures(t, hvCfg.KernelArgs)
	if len(features) != 1 || features[0].Name != "docker" {
		t.Fatalf("decoded features = %#v", features)
	}
	if got := features[0].Config["storage_driver"]; got != "vfs" {
		t.Fatalf("decoded storage_driver = %#v, want vfs", got)
	}
}

func TestBuildHypervisorConfigEncodesProcessInKernelArgs(t *testing.T) {
	cfg := config.Default()
	cfg.Process = &config.ProcessConfig{
		UID:               1000,
		GID:               1001,
		SupplementaryGIDs: []int{27, 44},
	}

	machine := NewMachine(cfg, RuntimeAssets{
		KernelPath:    "/tmp/vmlinux",
		RootfsPath:    "/tmp/rootfs.ext4",
		WorkspacePath: "/tmp/workspace.ext4",
		SocketPath:    "/tmp/firecracker.sock",
		VSockPath:     "/tmp/firecracker.vsock",
		LogPath:       "/tmp/firecracker.log",
		CID:           52,
	})

	hvCfg, err := machine.BuildHypervisorConfig()
	if err != nil {
		t.Fatalf("BuildHypervisorConfig() error = %v", err)
	}
	process := decodeKernelProcess(t, hvCfg.KernelArgs)
	if got, want := process.UID, 1000; got != want {
		t.Fatalf("decoded UID = %d, want %d", got, want)
	}
	if got, want := process.GID, 1001; got != want {
		t.Fatalf("decoded GID = %d, want %d", got, want)
	}
	if got, want := process.SupplementaryGIDs, []int{27, 44}; !equalIntSlice(got, want) {
		t.Fatalf("decoded supplementary gids = %#v, want %#v", got, want)
	}
}

func TestBuildHypervisorConfigIncludesGuestNetworkInterface(t *testing.T) {
	cfg := config.Default()

	machine := NewMachine(cfg, RuntimeAssets{
		KernelPath:    "/tmp/vmlinux",
		RootfsPath:    "/tmp/rootfs.ext4",
		WorkspacePath: "/tmp/workspace.ext4",
		SocketPath:    "/tmp/firecracker.sock",
		VSockPath:     "/tmp/firecracker.vsock",
		LogPath:       "/tmp/firecracker.log",
		CID:           52,
		Network: &GuestNetwork{
			TapName:    "keeltap0",
			MACAddress: "02:fc:00:00:00:01",
			GuestIP: net.IPNet{
				IP:   net.ParseIP("172.22.0.2"),
				Mask: net.CIDRMask(30, 32),
			},
			Gateway: net.ParseIP("172.22.0.1"),
		},
	})

	hvCfg, err := machine.BuildHypervisorConfig()
	if err != nil {
		t.Fatalf("BuildHypervisorConfig() error = %v", err)
	}
	if len(hvCfg.NetworkInterfaces) != 1 {
		t.Fatalf("len(NetworkInterfaces) = %d, want 1", len(hvCfg.NetworkInterfaces))
	}
	staticCfg := hvCfg.NetworkInterfaces[0]
	if got, want := staticCfg.HostDevName, "keeltap0"; got != want {
		t.Fatalf("HostDevName = %q, want %q", got, want)
	}
	if got, want := staticCfg.MACAddress, "02:fc:00:00:00:01"; got != want {
		t.Fatalf("MacAddress = %q, want %q", got, want)
	}
	if staticCfg.IPConfiguration == nil {
		t.Fatal("IPConfiguration = nil, want non-nil")
	}
	if got, want := staticCfg.IPConfiguration.Address.String(), "172.22.0.2/30"; got != want {
		t.Fatalf("IPAddr = %q, want %q", got, want)
	}
	if got, want := staticCfg.IPConfiguration.Gateway.String(), "172.22.0.1"; got != want {
		t.Fatalf("Gateway = %q, want %q", got, want)
	}
}

func TestPrepareCreatesHypervisorVM(t *testing.T) {
	assets := createRuntimeAssets(t)
	cfg := config.Default()

	var prepared bool
	var captured hypervisor.Config
	machine := NewMachine(cfg, assets)
	machine.PrepareNetwork = func(context.Context) (*GuestNetwork, func(), error) {
		return nil, func() {}, nil
	}
	machine.NewVM = func(cfg hypervisor.Config) (hypervisor.VM, error) {
		prepared = true
		captured = cfg
		return stubVM{}, nil
	}

	instance, cleanup, err := machine.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer cleanup()
	if instance == nil {
		t.Fatal("Prepare() returned nil VM")
	}
	if !prepared {
		t.Fatal("expected Prepare() to build a hypervisor VM")
	}
	if got, want := captured.SocketPath, assets.SocketPath; got != want {
		t.Fatalf("SocketPath = %q, want %q", got, want)
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
	machine.PrepareNetwork = func(context.Context) (*GuestNetwork, func(), error) {
		return nil, func() {}, nil
	}
	machine.AttachPTY = func(context.Context, hypervisor.VM) error { return nil }
	machine.NewVM = func(cfg hypervisor.Config) (hypervisor.VM, error) {
		for _, path := range []string{assets.SocketPath, assets.VSockPath, assets.LogPath} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("expected %q to be removed before launch, stat err=%v", path, err)
			}
		}
		return stubVM{}, nil
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

type stubVM struct {
	start func(context.Context) error
	wait  func(context.Context) error
}

func (m stubVM) Start(ctx context.Context) error {
	if m.start != nil {
		return m.start(ctx)
	}
	return nil
}

func (m stubVM) Stop(context.Context) error {
	return nil
}

func (m stubVM) Wait(ctx context.Context) error {
	if m.wait != nil {
		return m.wait(ctx)
	}
	return nil
}

func (stubVM) VSockListen(uint32) (net.Listener, error) {
	return nil, nil
}

func (stubVM) VSockConnect(uint32) (net.Conn, error) {
	server, client := net.Pipe()
	go server.Close()
	return client, nil
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

func decodeKernelFeatures(t *testing.T, kernelArgs string) []config.FeatureConfig {
	t.Helper()
	for _, field := range strings.Fields(kernelArgs) {
		if !strings.HasPrefix(field, "keel.features=") {
			continue
		}
		encoded := strings.TrimPrefix(field, "keel.features=")
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("DecodeString() error = %v", err)
		}
		var features []config.FeatureConfig
		if err := json.Unmarshal(data, &features); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		return features
	}
	t.Fatalf("keel.features not found in %q", kernelArgs)
	return nil
}

func decodeKernelProcess(t *testing.T, kernelArgs string) config.ProcessConfig {
	t.Helper()
	for _, field := range strings.Fields(kernelArgs) {
		if !strings.HasPrefix(field, "keel.process=") {
			continue
		}
		encoded := strings.TrimPrefix(field, "keel.process=")
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("DecodeString() error = %v", err)
		}
		var process config.ProcessConfig
		if err := json.Unmarshal(data, &process); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		return process
	}
	t.Fatalf("keel.process not found in %q", kernelArgs)
	return config.ProcessConfig{}
}

func equalIntSlice(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
