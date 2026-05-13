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
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
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
		MetadataPath:  "/tmp/bootmeta.ext4",
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
	if !strings.Contains(hvCfg.KernelArgs, "keel.meta=/dev/vdc") {
		t.Fatalf("KernelArgs missing metadata device: %q", hvCfg.KernelArgs)
	}
	if got, want := hvCfg.RootDrive.Path, "/tmp/rootfs.ext4"; got != want {
		t.Fatalf("RootDrive.Path = %q, want %q", got, want)
	}
	if len(hvCfg.ExtraDrives) != 2 {
		t.Fatalf("len(ExtraDrives) = %d, want 2", len(hvCfg.ExtraDrives))
	}
	if got, want := hvCfg.ExtraDrives[0].Path, "/tmp/workspace.ext4"; got != want {
		t.Fatalf("ExtraDrives[0].Path = %q, want %q", got, want)
	}
	if got, want := hvCfg.ExtraDrives[1].Path, "/tmp/bootmeta.ext4"; got != want {
		t.Fatalf("ExtraDrives[1].Path = %q, want %q", got, want)
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
		MetadataPath:  "/tmp/bootmeta.ext4",
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

func TestBuildHypervisorConfigIncludesConfiguredVolumes(t *testing.T) {
	cfg := config.Default()
	machine := NewMachine(cfg, RuntimeAssets{
		KernelPath:    "/tmp/vmlinux",
		RootfsPath:    "/tmp/rootfs.ext4",
		WorkspacePath: "/tmp/workspace.ext4",
		MetadataPath:  "/tmp/bootmeta.ext4",
		SocketPath:    "/tmp/firecracker.sock",
		VSockPath:     "/tmp/firecracker.vsock",
		LogPath:       "/tmp/firecracker.log",
		CID:           52,
		Volumes: []AttachedVolume{{
			ID:        "volume-00",
			ImagePath: "/tmp/volume-00.ext4",
			ReadOnly:  true,
		}},
	})

	hvCfg, err := machine.BuildHypervisorConfig()
	if err != nil {
		t.Fatalf("BuildHypervisorConfig() error = %v", err)
	}
	if len(hvCfg.ExtraDrives) != 3 {
		t.Fatalf("len(ExtraDrives) = %d, want 3", len(hvCfg.ExtraDrives))
	}
	if got, want := hvCfg.ExtraDrives[2].Path, "/tmp/volume-00.ext4"; got != want {
		t.Fatalf("ExtraDrives[2].Path = %q, want %q", got, want)
	}
	if !hvCfg.ExtraDrives[2].ReadOnly {
		t.Fatal("ExtraDrives[2].ReadOnly = false, want true")
	}
}

func TestBuildHypervisorConfigIncludesGuestNetworkInterface(t *testing.T) {
	cfg := config.Default()

	machine := NewMachine(cfg, RuntimeAssets{
		KernelPath:    "/tmp/vmlinux",
		RootfsPath:    "/tmp/rootfs.ext4",
		WorkspacePath: "/tmp/workspace.ext4",
		MetadataPath:  "/tmp/bootmeta.ext4",
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

func TestRunRechecksKVMAccessBeforeStartingVM(t *testing.T) {
	assets := createRuntimeAssets(t)
	cfg := config.Default()

	var kvmChecks int
	machine := NewMachine(cfg, assets)
	machine.EnsureKVMAccessFunc = func() error {
		kvmChecks++
		return nil
	}
	machine.PrepareNetwork = func(context.Context) (*GuestNetwork, func(), error) {
		return nil, func() {}, nil
	}
	machine.AttachPTY = func(context.Context, hypervisor.VM) error { return nil }
	machine.NewVM = func(hypervisor.Config) (hypervisor.VM, error) {
		return stubVM{
			start: func(context.Context) error {
				if kvmChecks != 2 {
					t.Fatalf("kvm checks before Start = %d, want 2", kvmChecks)
				}
				return nil
			},
		}, nil
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
		MetadataPath:  filepath.Join(dir, "bootmeta.ext4"),
		SocketPath:    filepath.Join(dir, "firecracker.sock"),
		VSockPath:     filepath.Join(dir, "firecracker.vsock"),
		LogPath:       filepath.Join(dir, "firecracker.log"),
		CID:           52,
		Manifest: pkgboot.Manifest{
			Command: []string{"/bin/sh"},
		},
	}
	for _, path := range []string{assets.KernelPath, assets.RootfsPath, assets.WorkspacePath, assets.MetadataPath} {
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
