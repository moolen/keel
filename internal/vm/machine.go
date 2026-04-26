package vm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/moolen/keel/internal/config"
	keelpty "github.com/moolen/keel/internal/pty"
	"github.com/sirupsen/logrus"
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
	NewFirecracker func(context.Context, firecracker.Config) (firecrackerMachine, error)
	AttachPTY      func(context.Context, string) error
	PrepareNetwork func(context.Context) (*GuestNetwork, func(), error)
}

type firecrackerMachine interface {
	Start(context.Context) error
	Wait(context.Context) error
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
		KernelArgs:      m.kernelArgs(),
		ForwardSignals:  []os.Signal{},
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
		NetworkInterfaces: m.networkInterfaces(),
	}, nil
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

func (m *Machine) Run(ctx context.Context) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if err := ensureKVMAccess(); err != nil {
		return err
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
			return err
		}
		m.Assets.Network = network
		if cleanup != nil {
			cleanupNetwork = cleanup
		}
	}
	defer cleanupNetwork()
	fcCfg, err := m.BuildConfig()
	if err != nil {
		return err
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
	if err := prepareRuntimePaths(m.Assets); err != nil {
		return err
	}

	newFirecracker := m.NewFirecracker
	if newFirecracker == nil {
		newFirecracker = m.defaultFirecrackerMachine
	}
	instance, err := newFirecracker(ctx, fcCfg)
	if err != nil {
		return err
	}
	if err := instance.Start(ctx); err != nil {
		return err
	}
	attachPTY := m.AttachPTY
	if attachPTY == nil {
		attachPTY = func(ctx context.Context, socketPath string) error {
			return (keelpty.Client{SocketPath: socketPath}).Run(ctx)
		}
	}
	if err := attachPTY(ctx, m.Assets.VSockPath); err != nil {
		return err
	}
	return instance.Wait(ctx)
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

func (m *Machine) defaultFirecrackerMachine(ctx context.Context, cfg firecracker.Config) (firecrackerMachine, error) {
	stdout := io.Discard
	stderr := io.Discard
	if m.Config.Verbose {
		stdout = os.Stdout
		stderr = os.Stderr
	}
	cmd := firecracker.VMCommandBuilder{}.
		WithBin("firecracker").
		WithSocketPath(cfg.SocketPath).
		WithStdin(nil).
		WithStdout(stdout).
		WithStderr(stderr).
		Build(ctx)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return firecracker.NewMachine(ctx, cfg,
		firecracker.WithProcessRunner(cmd),
		firecracker.WithLogger(logrus.NewEntry(logrus.New())),
	)
}

func (m *Machine) networkInterfaces() []firecracker.NetworkInterface {
	if m.Assets.Network == nil {
		return nil
	}
	return []firecracker.NetworkInterface{{
		StaticConfiguration: &firecracker.StaticNetworkConfiguration{
			HostDevName: m.Assets.Network.TapName,
			MacAddress:  m.Assets.Network.MACAddress,
			IPConfiguration: &firecracker.IPConfiguration{
				IPAddr:  net.IPNet{IP: append(net.IP(nil), m.Assets.Network.GuestIP.IP...), Mask: append(net.IPMask(nil), m.Assets.Network.GuestIP.Mask...)},
				Gateway: append(net.IP(nil), m.Assets.Network.Gateway...),
			},
		},
	}}
}
