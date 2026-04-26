package vm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	keelpty "github.com/moolen/keel/internal/pty"
)

type RuntimeAssets struct {
	KernelPath    string
	RootfsPath    string
	WorkspacePath string
	SocketPath    string
	VSockPath     string
	LogPath       string
	RuntimeDir    string
	CleanupDir    bool
	CID           uint32
	Network       *GuestNetwork
}

type Machine struct {
	Config         config.Config
	Assets         RuntimeAssets
	NewVM          func(hypervisor.Config) (hypervisor.VM, error)
	AttachPTY      func(context.Context, hypervisor.VM) error
	PrepareNetwork func(context.Context) (*GuestNetwork, func(), error)
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

	return hypervisor.Config{
		KernelPath: m.Assets.KernelPath,
		KernelArgs: m.kernelArgs(),
		RootDrive: hypervisor.DriveConfig{
			ID:     "rootfs",
			Path:   m.Assets.RootfsPath,
			IsRoot: true,
		},
		ExtraDrives: []hypervisor.DriveConfig{{
			ID:   "workspace",
			Path: m.Assets.WorkspacePath,
		}},
		VCPUs:             m.Config.Resources.VCPU,
		MemoryMB:          m.Config.Resources.MemoryMB,
		VSockCID:          m.Assets.CID,
		RuntimeDir:        m.Assets.RuntimeDir,
		SocketPath:        m.Assets.SocketPath,
		VSockPath:         m.Assets.VSockPath,
		LogPath:           m.Assets.LogPath,
		Verbose:           m.Config.Verbose,
		NetworkInterfaces: m.networkInterfaces(),
	}, nil
}

func (m *Machine) Prepare(ctx context.Context) (hypervisor.VM, func(), error) {
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	if err := ensureKVMAccess(); err != nil {
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
	if len(m.Config.Command) > 0 {
		encoded, err := encodeKernelCommand(m.Config.Command)
		if err == nil && encoded != "" {
			args = append(args, "keel.cmd="+encoded)
		}
	}
	if len(m.Config.Features) > 0 {
		encoded, err := encodeKernelFeatures(m.Config.Features)
		if err == nil && encoded != "" {
			args = append(args, "keel.features="+encoded)
		}
	}
	target := m.Config.Workspace.Target
	if target == "" {
		target = "/workspace"
	}
	args = append(args, "keel.cwd="+target)
	return strings.Join(args, " ")
}

func encodeKernelCommand(command []string) (string, error) {
	data, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func encodeKernelFeatures(features []config.FeatureConfig) (string, error) {
	data, err := json.Marshal(features)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
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
