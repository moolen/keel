package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/network"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/workspace"
)

type machineRunner interface {
	Run(context.Context) error
}

type HostRunner struct {
	RuntimeDir        string
	EnsureKernel      func(context.Context, string) (string, error)
	WorkspacePreparer func(workspace.PrepareOptions) (workspace.PrepareResult, error)
	PullImage         func(context.Context, string, string) (image.PullResult, error)
	MachineFactory    func(config.Config, vm.RuntimeAssets) machineRunner
}

func (r HostRunner) runtimeDir() string {
	if r.RuntimeDir != "" {
		return r.RuntimeDir
	}
	return filepath.Join(os.TempDir(), "keel-runtime")
}

func (r HostRunner) Run(ctx context.Context, req RunRequest) error {
	if req.Config.DryRun {
		out := req.Stdout
		if out == nil {
			out = io.Discard
		}
		_, err := fmt.Fprintf(out,
			"dry-run: image=%s workspace=%s target=%s command=%q\n",
			req.Config.Image,
			req.Config.Workspace.Mount,
			req.Config.Workspace.Target,
			req.Command,
		)
		return err
	}

	assets, err := r.prepareAssets(ctx, req.Config)
	if err != nil {
		return err
	}
	stopServices, err := r.startServices(ctx, req.Config, assets)
	if err != nil {
		return err
	}
	defer stopServices()
	factory := r.MachineFactory
	if factory == nil {
		factory = func(cfg config.Config, assets vm.RuntimeAssets) machineRunner {
			return vm.NewMachine(cfg, assets)
		}
	}
	machine := factory(req.Config, assets)
	return machine.Run(ctx)
}

func (r HostRunner) startServices(ctx context.Context, cfg config.Config, assets vm.RuntimeAssets) (func(), error) {
	serviceCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)

	tracker := network.NewTracker(60 * time.Second)
	engine := network.NewPolicyEngine(network.PolicyConfig{
		DNS: network.RuleSet{
			Allowed: cfg.Network.DNS.Allowed,
			Denied:  cfg.Network.DNS.Denied,
		},
		TCP: network.CIDRRuleSet{
			Allowed: cfg.Network.TCP.AllowedCIDRs,
			Denied:  cfg.Network.TCP.DeniedCIDRs,
		},
		TLS: network.RuleSet{
			Allowed: cfg.Network.TLS.AllowedSNI,
			Denied:  cfg.Network.TLS.DeniedSNI,
		},
		DenyIfNoSNI: cfg.Network.DenyIfNoSNI,
	}, tracker)
	dnsProxy := network.DNSProxy{
		Policy:  engine,
		Tracker: tracker,
	}
	tcpProxy := network.TCPProxy{
		Policy: engine,
	}
	go func() {
		errCh <- dnsProxy.Serve(serviceCtx, assets.VSockPath)
	}()
	go func() {
		errCh <- tcpProxy.Serve(serviceCtx, assets.VSockPath)
	}()
	socketPaths := []string{
		assets.VSockPath + "_3053",
		assets.VSockPath + "_3128",
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		ready := true
		for _, socketPath := range socketPaths {
			if _, err := os.Stat(socketPath); err != nil {
				ready = false
				break
			}
		}
		if ready {
			return cancel, nil
		}
		select {
		case err := <-errCh:
			cancel()
			return nil, err
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			return nil, fmt.Errorf("dns proxy did not start in time")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (r HostRunner) prepareAssets(ctx context.Context, cfg config.Config) (vm.RuntimeAssets, error) {
	ensureKernel := r.EnsureKernel
	if ensureKernel == nil {
		manager := vm.KernelManager{}
		ensureKernel = manager.Ensure
	}
	kernelPath, err := ensureKernel(ctx, cfg.Kernel.Path)
	if err != nil {
		return vm.RuntimeAssets{}, err
	}

	layout, err := image.ResolveCacheLayout(cfg.ImageCacheDir, cfg.Image)
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	if _, err := os.Stat(layout.RootfsPath); os.IsNotExist(err) {
		pull := r.PullImage
		if pull == nil {
			puller := image.Puller{GuestInit: defaultGuestAgentAssets}
			pull = puller.PullAndCache
		}
		result, err := pull(ctx, cfg.ImageCacheDir, cfg.Image)
		if err != nil {
			return vm.RuntimeAssets{}, err
		}
		layout = result.Layout
	} else if err != nil {
		return vm.RuntimeAssets{}, err
	}
	runtimeDir := r.runtimeDir()
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return vm.RuntimeAssets{}, err
	}
	workspacePath := filepath.Join(runtimeDir, "workspace.ext4")

	preparer := r.WorkspacePreparer
	if preparer == nil {
		preparer = workspace.PrepareImage
	}
	mountSource := cfg.Workspace.Mount
	if mountSource == "" {
		mountSource = "."
	}
	if _, err := preparer(workspace.PrepareOptions{
		SourceDir:  mountSource,
		ImagePath:  workspacePath,
		SizeMB:     max(cfg.Resources.DiskMB, 64),
		Label:      "workspace",
		Mountpoint: cfg.Workspace.Target,
	}); err != nil {
		return vm.RuntimeAssets{}, err
	}

	return vm.RuntimeAssets{
		KernelPath:    kernelPath,
		RootfsPath:    layout.RootfsPath,
		WorkspacePath: workspacePath,
		SocketPath:    filepath.Join(runtimeDir, "firecracker.sock"),
		VSockPath:     filepath.Join(runtimeDir, "firecracker.vsock"),
		LogPath:       filepath.Join(runtimeDir, "firecracker.log"),
		CID:           52,
	}, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
