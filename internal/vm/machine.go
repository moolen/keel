package vm

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	keelpty "github.com/moolen/keel/internal/pty"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

type RuntimeAssets struct {
	KernelPath    string
	RootfsPath    string
	WorkspacePath string
	MetadataPath  string
	SocketPath    string
	VSockPath     string
	LogPath       string
	RuntimeDir    string
	ControlDir    string
	CleanupDir    bool
	CID           uint32
	Network       *GuestNetwork
	Volumes       []AttachedVolume
	Manifest      pkgboot.Manifest
}

type AttachedVolume struct {
	ID         string
	ImagePath  string
	DevicePath string
	SourcePath string
	Target     string
	Kind       string
	Subpath    string
	ReadOnly   bool
	SyncBack   bool
	Ownership  string
}

type Machine struct {
	Config              config.Config
	Assets              RuntimeAssets
	NewVM               func(hypervisor.Config) (hypervisor.VM, error)
	AttachPTY           func(context.Context, hypervisor.VM) error
	PrepareNetwork      func(context.Context) (*GuestNetwork, func(), error)
	EnsureKVMAccessFunc func() error
}

func NewMachine(cfg config.Config, assets RuntimeAssets) *Machine {
	return &Machine{Config: cfg, Assets: assets}
}

func (m *Machine) Validate() error {
	switch {
	case m.Assets.KernelPath == "":
		return fmt.Errorf("kernel path is required")
	case m.Assets.RootfsPath == "":
		return fmt.Errorf("rootfs path is required")
	case m.Assets.WorkspacePath == "":
		return fmt.Errorf("workspace path is required")
	case m.Assets.MetadataPath == "":
		return fmt.Errorf("metadata path is required")
	case m.Assets.SocketPath == "":
		return fmt.Errorf("firecracker socket path is required")
	case m.Assets.VSockPath == "":
		return fmt.Errorf("vsock path is required")
	case m.Assets.CID < 3:
		return fmt.Errorf("vsock CID must be >= 3")
	}
	return nil
}

func (m *Machine) BuildHypervisorConfig() (hypervisor.Config, error) {
	if err := m.Validate(); err != nil {
		return hypervisor.Config{}, err
	}

	extraDrives := []hypervisor.DriveConfig{
		{
			ID:   "workspace",
			Path: m.Assets.WorkspacePath,
		},
		{
			ID:       "bootmeta",
			Path:     m.Assets.MetadataPath,
			ReadOnly: true,
		},
	}
	for _, volume := range m.Assets.Volumes {
		extraDrives = append(extraDrives, hypervisor.DriveConfig{
			ID:       volume.ID,
			Path:     volume.ImagePath,
			ReadOnly: volume.ReadOnly,
		})
	}

	return hypervisor.Config{
		KernelPath: m.Assets.KernelPath,
		KernelArgs: m.kernelArgs(),
		RootDrive: hypervisor.DriveConfig{
			ID:     "rootfs",
			Path:   m.Assets.RootfsPath,
			IsRoot: true,
		},
		ExtraDrives:       extraDrives,
		VCPUs:             m.Config.Resources.VCPU,
		MemoryMB:          m.Config.Resources.MemoryMB,
		VSockCID:          m.Assets.CID,
		RuntimeDir:        runtimeControlDir(m.Assets),
		SocketPath:        m.Assets.SocketPath,
		VSockPath:         m.Assets.VSockPath,
		LogPath:           m.Assets.LogPath,
		Verbose:           m.Config.Verbose,
		NetworkInterfaces: m.networkInterfaces(),
	}, nil
}

func runtimeControlDir(assets RuntimeAssets) string {
	if assets.ControlDir != "" {
		return assets.ControlDir
	}
	return assets.RuntimeDir
}

func (m *Machine) Prepare(ctx context.Context) (hypervisor.VM, func(), error) {
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	if err := m.EnsureKVMAccess(); err != nil {
		return nil, nil, err
	}

	cleanupNetwork := func() {}
	if m.Assets.Network == nil && m.Config.Network.Mode != "none" {
		prepareNetwork := m.PrepareNetwork
		if prepareNetwork == nil {
			prepareNetwork = func(ctx context.Context) (*GuestNetwork, func(), error) {
				return TapManager{}.Prepare(ctx)
			}
		}
		network, cleanup, err := prepareNetwork(ctx)
		if err != nil {
			return nil, nil, err
		}
		m.Assets.Network = network
		if cleanup != nil {
			cleanupNetwork = cleanup
		}
	}

	for _, asset := range []struct {
		label string
		path  string
	}{
		{label: "kernel image", path: m.Assets.KernelPath},
		{label: "rootfs", path: m.Assets.RootfsPath},
		{label: "workspace", path: m.Assets.WorkspacePath},
		{label: "metadata", path: m.Assets.MetadataPath},
	} {
		if _, err := os.Stat(asset.path); err != nil {
			cleanupNetwork()
			return nil, nil, fmt.Errorf("%s unavailable: %w", asset.label, err)
		}
	}
	if err := prepareRuntimePaths(m.Assets); err != nil {
		cleanupNetwork()
		return nil, nil, err
	}

	hvCfg, err := m.BuildHypervisorConfig()
	if err != nil {
		cleanupNetwork()
		return nil, nil, err
	}
	newVM := m.NewVM
	if newVM == nil {
		newVM = hypervisor.New
	}
	instance, err := newVM(hvCfg)
	if err != nil {
		cleanupNetwork()
		return nil, nil, err
	}
	return instance, cleanupNetwork, nil
}

func (m *Machine) Run(ctx context.Context) error {
	instance, cleanup, err := m.Prepare(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := m.EnsureKVMAccess(); err != nil {
		return err
	}
	if err := instance.Start(ctx); err != nil {
		return err
	}

	if err := m.AttachPTYToVM(ctx, instance); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = instance.Stop(stopCtx)
		return err
	}
	return instance.Wait(ctx)
}

func (m *Machine) EnsureKVMAccess() error {
	if m.EnsureKVMAccessFunc != nil {
		return m.EnsureKVMAccessFunc()
	}
	return ensureKVMAccess()
}

func (m *Machine) AttachPTYToVM(ctx context.Context, instance hypervisor.VM) error {
	attachPTY := m.AttachPTY
	if attachPTY == nil {
		attachPTY = func(ctx context.Context, instance hypervisor.VM) error {
			client := keelpty.Client{
				SocketPath: "ignored",
				Dial: func(_ context.Context, _ string, port uint32) (net.Conn, error) {
					return instance.VSockConnect(port)
				},
			}
			return client.Run(ctx)
		}
	}
	return attachPTY(ctx, instance)
}

func (m *Machine) kernelArgs() string {
	args := []string{
		"console=ttyS0",
		"reboot=k",
		"panic=1",
		"pci=off",
		"root=/dev/vda",
		"rw",
		"init=/usr/local/bin/keel-agent",
	}
	args = append(args, "keel.meta="+GuestBlockDevicePath(1))
	return strings.Join(args, " ")
}

func GuestBlockDevicePath(extraIndex int) string {
	return "/dev/vd" + string(rune('b'+extraIndex))
}

func prepareRuntimePaths(assets RuntimeAssets) error {
	for _, path := range []string{assets.SocketPath, assets.VSockPath, assets.LogPath} {
		if path == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (m *Machine) networkInterfaces() []hypervisor.NetworkInterfaceConfig {
	if m.Assets.Network == nil {
		return nil
	}
	return []hypervisor.NetworkInterfaceConfig{{
		HostDevName: m.Assets.Network.TapName,
		MACAddress:  m.Assets.Network.MACAddress,
		IPConfiguration: &hypervisor.IPConfiguration{
			Address: net.IPNet{
				IP:   append(net.IP(nil), m.Assets.Network.GuestIP.IP...),
				Mask: append(net.IPMask(nil), m.Assets.Network.GuestIP.Mask...),
			},
			Gateway: append(net.IP(nil), m.Assets.Network.Gateway...),
		},
	}}
}
