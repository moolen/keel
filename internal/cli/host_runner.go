package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/moolen/keel/internal/config"
	keelfeatures "github.com/moolen/keel/internal/features"
	"github.com/moolen/keel/internal/hypervisor"
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
	GuestAssets       func() (image.GuestAgentAssets, error)
	WorkspacePreparer func(workspace.PrepareOptions) (workspace.PrepareResult, error)
	SyncWorkspace     func(workspace.ImageSyncOptions) (workspace.SyncResult, error)
	PullImage         func(context.Context, string, string) (image.PullResult, error)
	MachineFactory    func(config.Config, vm.RuntimeAssets) machineRunner
	PrepareFeatures   func(string, []config.FeatureConfig) error
	ServiceStarter    func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error)
}

func (r HostRunner) runtimeDir() (string, error) {
	if r.RuntimeDir != "" {
		return r.RuntimeDir, nil
	}
	return os.MkdirTemp(os.TempDir(), "keel-runtime-*")
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
	defer r.cleanupRuntimeAssets(assets)
	r.warnKernelNetworkLimitations(req, assets)
	factory := r.MachineFactory
	if factory != nil {
		startServices := r.ServiceStarter
		if startServices == nil {
			startServices = r.startServices
		}
		stopServices, summary, err := startServices(ctx, req.Config, assets)
		if err != nil {
			return err
		}
		defer stopServices()
		defer r.printNetworkSummary(req, summary)
		machine := factory(req.Config, assets)
		runErr := machine.Run(ctx)
		syncErr := r.syncWorkspace(req, assets)
		switch {
		case runErr != nil && syncErr != nil:
			return fmt.Errorf("%w (workspace sync: %v)", runErr, syncErr)
		case runErr != nil:
			return runErr
		default:
			return syncErr
		}
	}

	machine := vm.NewMachine(req.Config, assets)
	runErr := r.runPreparedVM(ctx, req, machine)
	syncErr := r.syncWorkspace(req, assets)
	switch {
	case runErr != nil && syncErr != nil:
		return fmt.Errorf("%w (workspace sync: %v)", runErr, syncErr)
	case runErr != nil:
		return runErr
	default:
		return syncErr
	}
}

func (r HostRunner) runPreparedVM(ctx context.Context, req RunRequest, machine *vm.Machine) error {
	instance, cleanup, err := machine.Prepare(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	stopServices, summary, err := r.startVMServices(ctx, req.Config, instance)
	if err != nil {
		return err
	}
	defer stopServices()
	defer r.printNetworkSummary(req, summary)

	if err := instance.Start(ctx); err != nil {
		return err
	}
	if err := machine.AttachPTYToVM(ctx, instance); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = instance.Stop(stopCtx)
		return err
	}
	return instance.Wait(ctx)
}

func (r HostRunner) warnKernelNetworkLimitations(req RunRequest, assets vm.RuntimeAssets) {
	if !networkPolicyConfigured(req.Config) {
		return
	}
	if assets.KernelPath != vm.DefaultKernelPath() {
		return
	}
	stderr := req.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	_, _ = fmt.Fprintln(stderr, "warning: transparent tcp redirect is unavailable on the default kernel; direct tap egress remains blocked, so only proxy-aware clients will work until you provide a custom kernel with netfilter support")
}

func networkPolicyConfigured(cfg config.Config) bool {
	return len(cfg.Network.DNS.Allowed) > 0 ||
		len(cfg.Network.DNS.Denied) > 0 ||
		len(cfg.Network.TCP.AllowedCIDRs) > 0 ||
		len(cfg.Network.TCP.DeniedCIDRs) > 0 ||
		len(cfg.Network.TLS.AllowedSNI) > 0 ||
		len(cfg.Network.TLS.DeniedSNI) > 0 ||
		cfg.Network.DenyIfNoSNI
}

func (r HostRunner) startServices(ctx context.Context, cfg config.Config, assets vm.RuntimeAssets) (func(), *network.Summary, error) {
	serviceCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)

	tracker := network.NewTracker(60 * time.Second)
	summary := network.NewSummary()
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
		Summary: summary,
	}
	tcpProxy := network.TCPProxy{
		Policy:  engine,
		Summary: summary,
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
			return cancel, summary, nil
		}
		select {
		case err := <-errCh:
			cancel()
			return nil, nil, err
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			return nil, nil, fmt.Errorf("dns proxy did not start in time")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (r HostRunner) startVMServices(ctx context.Context, cfg config.Config, instance hypervisor.VM) (func(), *network.Summary, error) {
	serviceCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 2)

	tracker := network.NewTracker(60 * time.Second)
	summary := network.NewSummary()
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
		Summary: summary,
	}
	tcpProxy := network.TCPProxy{
		Policy:  engine,
		Summary: summary,
	}

	dnsListener, err := instance.VSockListen(3053)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	tcpListener, err := instance.VSockListen(3128)
	if err != nil {
		cancel()
		_ = dnsListener.Close()
		return nil, nil, err
	}

	go func() {
		errCh <- dnsProxy.ServeListener(serviceCtx, dnsListener)
	}()
	go func() {
		errCh <- tcpProxy.ServeListener(serviceCtx, tcpListener)
	}()

	select {
	case err := <-errCh:
		cancel()
		return nil, nil, err
	default:
	}
	return cancel, summary, nil
}

func (r HostRunner) printNetworkSummary(req RunRequest, summary *network.Summary) {
	if summary == nil {
		return
	}
	stderr := req.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	_ = summary.WriteReport(stderr)
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
	guestTrust, err := guestTrustAssetsForConfig(cfg)
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	var guestAssets image.GuestAgentAssets
	if _, err := os.Stat(layout.RootfsPath); os.IsNotExist(err) {
		pull := r.PullImage
		if pull == nil {
			puller := image.Puller{
				GuestInit:  defaultGuestAgentAssets,
				GuestTrust: guestTrust,
			}
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
	loadGuestAssets := r.GuestAssets
	if loadGuestAssets == nil {
		loadGuestAssets = defaultGuestAgentAssets
	}
	guestAssets, err = loadGuestAssets()
	if err != nil {
		guestAssets = image.GuestAgentAssets{}
	}
	if len(guestAssets.Binary) > 0 {
		if _, err := image.EnsureGuestAgent(layout.RootfsPath, layout.AgentPath, guestAssets); err != nil {
			return vm.RuntimeAssets{}, err
		}
	}
	if err := image.InjectGuestTrust(layout.RootfsPath, guestTrust); err != nil {
		return vm.RuntimeAssets{}, err
	}
	if err := r.prepareFeatures(layout.RootfsPath, cfg.Features); err != nil {
		return vm.RuntimeAssets{}, err
	}
	runtimeDir, err := r.runtimeDir()
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return vm.RuntimeAssets{}, err
	}
	workspacePath := filepath.Join(runtimeDir, "workspace.ext4")
	assets := vm.RuntimeAssets{
		KernelPath:    kernelPath,
		RootfsPath:    layout.RootfsPath,
		WorkspacePath: workspacePath,
		SocketPath:    filepath.Join(runtimeDir, "firecracker.sock"),
		VSockPath:     filepath.Join(runtimeDir, "firecracker.vsock"),
		LogPath:       filepath.Join(runtimeDir, "firecracker.log"),
		RuntimeDir:    runtimeDir,
		CleanupDir:    r.RuntimeDir == "",
		CID:           52,
	}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			r.cleanupRuntimeAssets(assets)
		}
	}()

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

	cleanupOnError = false
	return assets, nil
}

func guestTrustAssetsForConfig(cfg config.Config) (image.GuestTrustAssets, error) {
	if !cfg.Network.MITM.Enabled || !cfg.Network.MITM.CA.InstallSystem {
		return image.GuestTrustAssets{}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return image.GuestTrustAssets{}, err
	}
	caDir := filepath.Join(home, ".local", "share", "keel", "ca")
	ca, err := network.LoadOrCreateCA(network.CAOptions{
		Dir:  caDir,
		Name: cfg.Network.MITM.CA.Name,
	})
	if err != nil {
		return image.GuestTrustAssets{}, err
	}
	return image.GuestTrustAssets{
		Enabled:   true,
		CACertPEM: ca.CertPEM,
	}, nil
}

func (r HostRunner) syncWorkspace(req RunRequest, assets vm.RuntimeAssets) error {
	if !req.Config.Workspace.SyncBack {
		return nil
	}
	syncWorkspace := r.SyncWorkspace
	if syncWorkspace == nil {
		syncWorkspace = workspace.SyncImage
	}
	hostDir := req.Config.Workspace.Mount
	if hostDir == "" {
		hostDir = "."
	}
	_, err := syncWorkspace(workspace.ImageSyncOptions{
		HostDir:     hostDir,
		ImagePath:   assets.WorkspacePath,
		SyncDeletes: req.Config.Workspace.SyncDeletes,
		Confirm:     req.Config.Workspace.SyncConfirm,
		In:          req.Stdin,
		Out:         req.Stderr,
	})
	return err
}

func (r HostRunner) prepareFeatures(rootfsPath string, configured []config.FeatureConfig) error {
	if len(configured) == 0 {
		return nil
	}
	prepare := r.PrepareFeatures
	if prepare == nil {
		registry := keelfeatures.NewRegistry()
		if err := registry.Register(keelfeatures.NewDockerFeature()); err != nil {
			return err
		}
		prepare = func(rootfsPath string, configured []config.FeatureConfig) error {
			items := make([]keelfeatures.ConfiguredFeature, 0, len(configured))
			for _, feature := range configured {
				items = append(items, keelfeatures.ConfiguredFeature{
					Name:   feature.Name,
					Config: feature.Config,
				})
			}
			if err := registry.Validate(items); err != nil {
				return err
			}
			return registry.PrepareRootfs(rootfsPath, items)
		}
	}
	return prepare(rootfsPath, configured)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (r HostRunner) cleanupRuntimeAssets(assets vm.RuntimeAssets) {
	if assets.CleanupDir && assets.RuntimeDir != "" {
		_ = os.RemoveAll(assets.RuntimeDir)
		return
	}
	for _, path := range []string{
		assets.WorkspacePath,
		assets.SocketPath,
		assets.VSockPath,
		assets.VSockPath + "_3053",
		assets.VSockPath + "_3128",
		assets.LogPath,
	} {
		if path == "" {
			continue
		}
		_ = os.RemoveAll(path)
	}
}
