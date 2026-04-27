//go:build linux

package hypervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	sdk "github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/sirupsen/logrus"
)

type firecrackerMachine interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	Wait(context.Context) error
	StopVMM() error
}

type firecrackerVM struct {
	cfg       Config
	machine   firecrackerMachine
	listeners map[uint32]net.Listener
	mu        sync.Mutex
}

func New(cfg Config) (VM, error) {
	if cfg.KernelPath == "" {
		return nil, fmt.Errorf("kernel path is required")
	}
	if cfg.RootDrive.Path == "" {
		return nil, fmt.Errorf("root drive path is required")
	}
	if cfg.SocketPath == "" {
		return nil, fmt.Errorf("socket path is required")
	}
	if cfg.VSockPath == "" {
		return nil, fmt.Errorf("vsock path is required")
	}
	if cfg.VSockCID < 3 {
		return nil, fmt.Errorf("vsock CID must be >= 3")
	}
	if _, err := exec.LookPath("firecracker"); err != nil {
		return nil, fmt.Errorf("firecracker not installed or not in PATH")
	}
	return &firecrackerVM{
		cfg:       cfg,
		listeners: make(map[uint32]net.Listener),
	}, nil
}

func (vm *firecrackerVM) Start(ctx context.Context) error {
	if err := os.MkdirAll(vm.cfg.RuntimeDir, 0o755); err != nil {
		return err
	}
	for _, path := range []string{vm.cfg.SocketPath, vm.cfg.VSockPath, vm.cfg.LogPath} {
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

	fcCfg := vm.buildConfig()
	stdout := io.Discard
	stderr := io.Discard
	if vm.cfg.Verbose {
		stdout = os.Stdout
		stderr = os.Stderr
	}
	cmd := sdk.VMCommandBuilder{}.
		WithBin("firecracker").
		WithSocketPath(fcCfg.SocketPath).
		WithStdin(nil).
		WithStdout(stdout).
		WithStderr(stderr).
		Build(ctx)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	instance, err := sdk.NewMachine(ctx, fcCfg,
		sdk.WithProcessRunner(cmd),
		sdk.WithLogger(logrus.NewEntry(logrus.New())),
	)
	if err != nil {
		return err
	}
	vm.machine = instance
	return vm.machine.Start(ctx)
}

func (vm *firecrackerVM) Stop(ctx context.Context) error {
	if vm.machine == nil {
		return nil
	}
	if err := vm.machine.Shutdown(ctx); err == nil {
		return nil
	} else if ctx.Err() == nil {
		if stopErr := vm.machine.StopVMM(); stopErr != nil {
			return errors.Join(err, stopErr)
		}
		return err
	}
	return vm.machine.StopVMM()
}

func (vm *firecrackerVM) Wait(ctx context.Context) error {
	if vm.machine == nil {
		return nil
	}
	defer vm.cleanup()
	return vm.machine.Wait(ctx)
}

func (vm *firecrackerVM) VSockListen(port uint32) (net.Listener, error) {
	path := fmt.Sprintf("%s_%d", vm.cfg.VSockPath, port)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, fmt.Errorf("vsock listen port %d: %w", port, err)
	}
	vm.mu.Lock()
	vm.listeners[port] = ln
	vm.mu.Unlock()
	return ln, nil
}

func (vm *firecrackerVM) VSockConnect(port uint32) (net.Conn, error) {
	return dialVSock(context.Background(), vm.cfg.VSockPath, port)
}

func (vm *firecrackerVM) buildConfig() sdk.Config {
	drives := make([]models.Drive, 0, 1+len(vm.cfg.ExtraDrives))
	drives = append(drives, models.Drive{
		DriveID:      sdk.String(vm.cfg.RootDrive.ID),
		PathOnHost:   sdk.String(vm.cfg.RootDrive.Path),
		IsRootDevice: sdk.Bool(true),
		IsReadOnly:   sdk.Bool(vm.cfg.RootDrive.ReadOnly),
	})
	for _, drive := range vm.cfg.ExtraDrives {
		drives = append(drives, models.Drive{
			DriveID:      sdk.String(drive.ID),
			PathOnHost:   sdk.String(drive.Path),
			IsRootDevice: sdk.Bool(false),
			IsReadOnly:   sdk.Bool(drive.ReadOnly),
		})
	}

	netifs := make([]sdk.NetworkInterface, 0, len(vm.cfg.NetworkInterfaces))
	for _, nic := range vm.cfg.NetworkInterfaces {
		staticCfg := &sdk.StaticNetworkConfiguration{
			MacAddress:  nic.MACAddress,
			HostDevName: nic.HostDevName,
		}
		if nic.IPConfiguration != nil {
			staticCfg.IPConfiguration = &sdk.IPConfiguration{
				IPAddr:  nic.IPConfiguration.Address,
				Gateway: nic.IPConfiguration.Gateway,
			}
		}
		netifs = append(netifs, sdk.NetworkInterface{StaticConfiguration: staticCfg})
	}

	return sdk.Config{
		SocketPath:      vm.cfg.SocketPath,
		LogPath:         vm.cfg.LogPath,
		KernelImagePath: vm.cfg.KernelPath,
		InitrdPath:      vm.cfg.InitrdPath,
		KernelArgs:      vm.cfg.KernelArgs,
		ForwardSignals:  []os.Signal{},
		Drives:          drives,
		VsockDevices: []sdk.VsockDevice{{
			ID:   "keel-vsock",
			Path: vm.cfg.VSockPath,
			CID:  vm.cfg.VSockCID,
		}},
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  sdk.Int64(int64(vm.cfg.VCPUs)),
			MemSizeMib: sdk.Int64(int64(vm.cfg.MemoryMB)),
			Smt:        sdk.Bool(false),
		},
		NetworkInterfaces: netifs,
	}
}

func (vm *firecrackerVM) cleanup() {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	for port, listener := range vm.listeners {
		_ = listener.Close()
		delete(vm.listeners, port)
		_ = os.Remove(fmt.Sprintf("%s_%d", vm.cfg.VSockPath, port))
	}
	for _, path := range []string{vm.cfg.SocketPath, vm.cfg.VSockPath} {
		if path != "" {
			_ = os.Remove(path)
		}
	}
}

func dialVSock(ctx context.Context, socketPath string, port uint32) (net.Conn, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
		defer func() {
			_ = conn.SetDeadline(time.Time{})
		}()
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		_ = conn.Close()
		return nil, err
	}
	line, err := readAckLine(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !strings.HasPrefix(line, "OK ") {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock connect rejected: %s", strings.TrimSpace(line))
	}
	return conn, nil
}

func readAckLine(r io.Reader) (string, error) {
	buf := make([]byte, 0, 32)
	var single [1]byte
	for {
		if _, err := io.ReadFull(r, single[:]); err != nil {
			return "", err
		}
		buf = append(buf, single[0])
		if single[0] == '\n' {
			return string(buf), nil
		}
	}
}
