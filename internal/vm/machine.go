package vm

import (
	"context"
	"errors"
	"fmt"
	"os"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/moolen/keel/internal/config"
)

var ErrNotImplemented = errors.New("vm lifecycle not implemented yet")

type RuntimeAssets struct {
	KernelPath    string
	RootfsPath    string
	WorkspacePath string
	SocketPath    string
	VSockPath     string
	LogPath       string
	CID           uint32
}

type Machine struct {
	Config config.Config
	Assets RuntimeAssets
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

func (m *Machine) BuildConfig() (firecracker.Config, error) {
	if err := m.Validate(); err != nil {
		return firecracker.Config{}, err
	}

	rootDrive := models.Drive{
		DriveID:      firecracker.String("rootfs"),
		PathOnHost:   firecracker.String(m.Assets.RootfsPath),
		IsRootDevice: firecracker.Bool(true),
		IsReadOnly:   firecracker.Bool(false),
	}
	workspaceDrive := models.Drive{
		DriveID:      firecracker.String("workspace"),
		PathOnHost:   firecracker.String(m.Assets.WorkspacePath),
		IsRootDevice: firecracker.Bool(false),
		IsReadOnly:   firecracker.Bool(false),
	}

	return firecracker.Config{
		SocketPath:      m.Assets.SocketPath,
		LogPath:         m.Assets.LogPath,
		KernelImagePath: m.Assets.KernelPath,
		KernelArgs:      "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/bin/keel-agent",
		Drives:          []models.Drive{rootDrive, workspaceDrive},
		VsockDevices: []firecracker.VsockDevice{
			{
				ID:   "keel-vsock",
				Path: m.Assets.VSockPath,
				CID:  m.Assets.CID,
			},
		},
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  firecracker.Int64(int64(m.Config.Resources.VCPU)),
			MemSizeMib: firecracker.Int64(int64(m.Config.Resources.MemoryMB)),
			Smt:        firecracker.Bool(false),
		},
	}, nil
}

func (m *Machine) Run(context.Context) error {
	if err := m.Validate(); err != nil {
		return err
	}
	fcCfg, err := m.BuildConfig()
	if err != nil {
		return err
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("kvm unavailable: %w", err)
	}
	if _, err := os.Stat(fcCfg.KernelImagePath); err != nil {
		return fmt.Errorf("kernel image unavailable: %w", err)
	}
	if _, err := os.Stat(m.Assets.RootfsPath); err != nil {
		return fmt.Errorf("rootfs unavailable: %w", err)
	}
	if _, err := os.Stat(m.Assets.WorkspacePath); err != nil {
		return fmt.Errorf("workspace unavailable: %w", err)
	}
	return ErrNotImplemented
}
