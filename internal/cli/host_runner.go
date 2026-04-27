package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	bootmeta "github.com/moolen/keel/internal/bootmanifest"
	"github.com/moolen/keel/internal/config"
	keelfeatures "github.com/moolen/keel/internal/features"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/network"
	keelpty "github.com/moolen/keel/internal/pty"
	"github.com/moolen/keel/internal/runtimeenv"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/volume"
	"github.com/moolen/keel/internal/workspace"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
	"golang.org/x/term"
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
	VolumePreparer    func(volume.PrepareOptions) (volume.PrepareResult, error)
	SyncVolume        func(volume.SyncOptions) error
	ResolveEnv        func(config.EnvConfig) (map[string]string, error)
	WriteBootManifest func(string, pkgboot.Manifest) error
	PullImage         func(context.Context, string, string) (image.PullResult, error)
	MachineFactory    func(config.Config, vm.RuntimeAssets) machineRunner
	PrepareFeatures   func(string, []config.FeatureConfig) error
	ServiceStarter    func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error)
	ProgressFactory   func(io.Writer, int) (progressReporter, error)
	ProgressEnabled   func(io.Writer) bool
}

const startupPhaseTotal = 10

func startupPhase(index int, title, detail string) startupStep {
	return startupStep{
		Index:  index,
		Total:  startupPhaseTotal,
		Title:  title,
		Detail: detail,
	}
}

func kernelProgressStep(update vm.KernelProgress) startupStep {
	step := startupPhase(3, "ensuring kernel", "resolving guest kernel image")
	switch {
	case update.Total > 0:
		return step.WithProgress(update.Current, update.Total, fmt.Sprintf("%s (%s / %s)", update.Phase, formatBytes(update.Current), formatBytes(update.Total)))
	case update.Current > 0:
		return step.Complete(update.Phase)
	case update.Phase != "":
		step.Detail = update.Phase
	}
	return step
}

func imagePullProgressStep(update image.PullProgress) startupStep {
	step := startupPhase(4, "pulling oci image", "resolving cached rootfs and image layers")
	switch update.Phase {
	case image.PullPhaseResolve:
		return step.WithProgress(5, 100, update.Phase.String())
	case image.PullPhaseDownload:
		current := int64(10)
		if update.Total > 0 {
			current += (update.Current * 70) / update.Total
			return step.WithProgress(current, 100, fmt.Sprintf("%s (%s / %s)", update.Phase.String(), formatBytes(update.Current), formatBytes(update.Total)))
		}
		return step.WithProgress(current, 100, update.Phase.String())
	case image.PullPhaseExtract:
		return step.WithProgress(85, 100, update.Phase.String())
	case image.PullPhaseBuildRootfs:
		return step.WithProgress(95, 100, update.Phase.String())
	case image.PullPhaseReady:
		return step.Complete(update.Phase.String())
	default:
		if update.Phase != "" {
			step.Detail = update.Phase.String()
		}
		return step
	}
}

func (r HostRunner) runtimeDir() (string, error) {
	if r.RuntimeDir != "" {
		return r.RuntimeDir, nil
	}
	return os.MkdirTemp(os.TempDir(), "keel-runtime-*")
}

func (r HostRunner) Run(ctx context.Context, req RunRequest) error {
	if req.Config.DryRun {
		cfg, err := r.runtimeConfig(req.Config)
		if err != nil {
			return err
		}
		out := req.Stdout
		if out == nil {
			out = io.Discard
		}
		_, err = fmt.Fprintf(out,
			"dry-run: image=%s workspace=%s target=%s command=%q\n",
			cfg.Image,
			cfg.Workspace.Mount,
			cfg.Workspace.Target,
			req.Command,
		)
		return err
	}

	progress := r.newProgressReporter(req)
	defer progress.Stop()

	progress.Step(startupPhase(1, "resolving config", "merging runtime configuration"))
	progress.Step(startupPhase(2, "resolving runtime env", "materializing env and feature config"))
	cfg, err := r.runtimeConfig(req.Config)
	if err != nil {
		return err
	}

	assets, err := r.prepareAssets(ctx, cfg, progress)
	if err != nil {
		return err
	}
	defer r.cleanupRuntimeAssets(assets)
	req.Config = cfg
	r.warnKernelNetworkLimitations(req, assets)
	r.warnNetworkAuditMode(req)
	factory := r.MachineFactory
	if factory != nil {
		startServices := r.ServiceStarter
		if startServices == nil {
			startServices = r.startServices
		}
		progress.Step(startupPhase(9, "starting vm services", "starting dns and tcp policy proxies"))
		stopServices, summary, err := startServices(ctx, cfg, assets)
		if err != nil {
			return err
		}
		defer stopServices()
		defer r.printNetworkSummary(req, summary)
		machine := factory(cfg, assets)
		progress.Step(startupPhase(10, "booting vm and attaching terminal", "handing off to guest process"))
		progress.Stop()
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

	machine := vm.NewMachine(cfg, assets)
	runErr := r.runPreparedVM(ctx, req, machine, progress)
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

func (r HostRunner) runPreparedVM(ctx context.Context, req RunRequest, machine *vm.Machine, progress progressReporter) error {
	if machine.AttachPTY == nil {
		machine.AttachPTY = func(ctx context.Context, instance hypervisor.VM) error {
			stdin := forwardedPTYStdin(req)
			if stdin == nil {
				devNull, err := os.Open(os.DevNull)
				if err != nil {
					return err
				}
				defer func() { _ = devNull.Close() }()
				stdin = devNull
			}
			client := keelpty.Client{
				SocketPath: "ignored",
				Stdin:      stdin,
				Stdout:     req.Stdout,
				Dial: func(_ context.Context, _ string, port uint32) (net.Conn, error) {
					return instance.VSockConnect(port)
				},
			}
			return client.Run(ctx)
		}
	}
	instance, cleanup, err := machine.Prepare(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	progress.Step(startupPhase(9, "starting vm services", "starting dns and tcp policy proxies"))
	stopServices, summary, err := r.startVMServices(ctx, req.Config, instance)
	if err != nil {
		return err
	}
	defer stopServices()
	defer r.printNetworkSummary(req, summary)

	progress.Step(startupPhase(10, "booting vm and attaching terminal", "handing off to guest process"))
	if err := instance.Start(ctx); err != nil {
		return err
	}
	progress.Stop()
	if err := machine.AttachPTYToVM(ctx, instance); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = instance.Stop(stopCtx)
		return diagnoseAttachFailure(err, req.Config.Image)
	}
	return instance.Wait(ctx)
}

func diagnoseAttachFailure(err error, imageRef string) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	if strings.Contains(text, "connection refused") || strings.Contains(text, "no such file or directory") {
		msg := "guest exited before the control channel became available"
		if imageRef != "" && !strings.Contains(imageRef, "@") {
			msg += fmt.Sprintf("; if %q is a mutable tag, refresh the cached image with `keel image pull %s`", imageRef, imageRef)
		}
		return fmt.Errorf("%s: %w", msg, err)
	}
	return err
}

func forwardedPTYStdin(req RunRequest) *os.File {
	stdin, ok := req.Stdin.(*os.File)
	if !ok {
		return nil
	}
	if req.Config.Workspace.SyncConfirm && !term.IsTerminal(int(stdin.Fd())) {
		return nil
	}
	return stdin
}

func (r HostRunner) newProgressReporter(req RunRequest) progressReporter {
	output := req.Stderr
	if output == nil {
		output = os.Stderr
	}
	return newStartupProgressReporter(output, startupPhaseTotal, startupProgressOptions{
		DryRun:      req.Config.DryRun,
		Interactive: r.ProgressEnabled,
		Factory:     r.ProgressFactory,
	})
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

func (r HostRunner) warnNetworkAuditMode(req RunRequest) {
	if !req.Config.Network.Audit {
		return
	}
	stderr := req.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	_, _ = fmt.Fprintln(stderr, "warning: network audit mode enabled; proxy policy denies will be allowed at runtime and reported as would_deny")
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

	dnsProxy, tcpProxy, summary, err := buildNetworkServices(cfg)
	if err != nil {
		cancel()
		return nil, nil, err
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

	dnsProxy, tcpProxy, summary, err := buildNetworkServices(cfg)
	if err != nil {
		cancel()
		return nil, nil, err
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

func (r HostRunner) prepareAssets(ctx context.Context, cfg config.Config, progress progressReporter) (vm.RuntimeAssets, error) {
	ensureKernel := r.EnsureKernel
	if ensureKernel == nil {
		manager := vm.KernelManager{
			Progress: func(update vm.KernelProgress) {
				progress.Step(kernelProgressStep(update))
			},
		}
		ensureKernel = manager.Ensure
	}
	progress.Step(startupPhase(3, "ensuring kernel", "resolving guest kernel image"))
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
	progress.Step(startupPhase(4, "pulling oci image", "resolving cached rootfs and image layers"))
	var guestAssets image.GuestAgentAssets
	if _, err := os.Stat(layout.RootfsPath); os.IsNotExist(err) {
		pull := r.PullImage
		if pull == nil {
			puller := image.Puller{
				GuestInit:  defaultGuestAgentAssets,
				GuestTrust: guestTrust,
				Progress: func(update image.PullProgress) {
					progress.Step(imagePullProgressStep(update))
				},
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
	} else {
		progress.Step(startupPhase(4, "pulling oci image", "resolving cached rootfs and image layers").Complete("using cached rootfs image"))
	}
	loadGuestAssets := r.GuestAssets
	if loadGuestAssets == nil {
		loadGuestAssets = defaultGuestAgentAssets
	}
	progress.Step(startupPhase(5, "preparing guest assets", "injecting guest binaries, trust, and rootfs features"))
	guestAssets, err = loadGuestAssets()
	if err != nil {
		return vm.RuntimeAssets{}, fmt.Errorf("load guest assets: %w", err)
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
		MetadataPath:  filepath.Join(runtimeDir, "bootmeta.ext4"),
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
	progress.Step(startupPhase(6, "preparing workspace image", "copying workspace into an ext4 snapshot"))
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
	progress.Step(startupPhase(7, "preparing extra volumes", "materializing additional writable and read-only volumes"))
	volumes, err := r.prepareVolumes(cfg, runtimeDir)
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	assets.Volumes = volumes
	assets.Manifest = buildBootManifest(cfg, volumes)
	writeBootManifest := r.WriteBootManifest
	if writeBootManifest == nil {
		writeBootManifest = bootmeta.WriteImage
	}
	progress.Step(startupPhase(8, "writing boot metadata image", "packing command, env, process, and volume metadata"))
	if err := writeBootManifest(assets.MetadataPath, assets.Manifest); err != nil {
		return vm.RuntimeAssets{}, err
	}

	cleanupOnError = false
	return assets, nil
}

func guestTrustAssetsForConfig(cfg config.Config) (image.GuestTrustAssets, error) {
	if !cfg.Network.MITM.Enabled || !cfg.Network.MITM.CA.InstallSystem {
		return image.GuestTrustAssets{}, nil
	}
	ca, err := loadMITMCA(cfg)
	if err != nil {
		return image.GuestTrustAssets{}, err
	}
	return image.GuestTrustAssets{
		Enabled:   true,
		CACertPEM: ca.CertPEM,
	}, nil
}

func (r HostRunner) runtimeConfig(cfg config.Config) (config.Config, error) {
	updated := cfg
	resolveEnv := r.ResolveEnv
	if resolveEnv == nil {
		resolveEnv = runtimeenv.Resolve
	}
	values, err := resolveEnv(cfg.Env)
	if err != nil {
		return config.Config{}, err
	}
	updated.RuntimeEnv = values
	features, err := runtimeFeatureConfig(cfg)
	if err != nil {
		return config.Config{}, err
	}
	updated.Features = features
	return updated, nil
}

func runtimeFeatureConfig(cfg config.Config) ([]config.FeatureConfig, error) {
	if len(cfg.Features) == 0 {
		return nil, nil
	}
	features := append([]config.FeatureConfig(nil), cfg.Features...)
	if !cfg.Network.MITM.Enabled || !cfg.Network.MITM.CA.InstallDocker {
		return features, nil
	}
	ca, err := loadMITMCA(cfg)
	if err != nil {
		return nil, err
	}
	for i := range features {
		if features[i].Name != "docker" {
			continue
		}
		cloned := map[string]any{}
		for key, value := range features[i].Config {
			cloned[key] = value
		}
		cloned["mitm_ca_pem"] = string(ca.CertPEM)
		features[i].Config = cloned
	}
	return features, nil
}

func buildNetworkServices(cfg config.Config) (network.DNSProxy, network.TCPProxy, *network.Summary, error) {
	tracker := network.NewTracker(60 * time.Second)
	summary := network.NewSummary()
	events := network.NewEventLogger(os.Stderr)
	httpPolicy := network.HTTPPolicyConfig{
		Default: cfg.Network.HTTP.Default,
		Rules:   httpRulesFromConfig(cfg.Network.HTTP.Rules),
		Audit:   cfg.Network.Audit,
	}
	engine := network.NewPolicyEngine(network.PolicyConfig{
		Audit: cfg.Network.Audit,
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
		HTTP:        httpPolicy,
		DenyIfNoSNI: cfg.Network.DenyIfNoSNI,
	}, tracker)
	dnsProxy := network.DNSProxy{
		Policy:  engine,
		Tracker: tracker,
		Summary: summary,
		Events:  events,
	}
	tcpProxy := network.TCPProxy{
		Policy:  engine,
		Summary: summary,
		Events:  events,
	}
	if cfg.Network.MITM.Enabled {
		ca, err := loadMITMCA(cfg)
		if err != nil {
			return network.DNSProxy{}, network.TCPProxy{}, nil, err
		}
		tcpProxy.MITM = &network.MITMProxy{
			Enabled:     true,
			BypassHosts: append([]string(nil), cfg.Network.MITM.Bypass.Hosts...),
			BypassSNI:   append([]string(nil), cfg.Network.MITM.Bypass.SNI...),
			CA:          ca,
			Policy:      network.NewHTTPPolicy(httpPolicy),
			Summary:     summary,
		}
	}
	return dnsProxy, tcpProxy, summary, nil
}

func httpRulesFromConfig(items []config.HTTPRuleConfig) []network.HTTPRule {
	rules := make([]network.HTTPRule, 0, len(items))
	for _, item := range items {
		rules = append(rules, network.HTTPRule{
			Action:  item.Action,
			Host:    item.Host,
			Methods: append([]string(nil), item.Methods...),
			Paths:   append([]string(nil), item.Paths...),
		})
	}
	return rules
}

func loadMITMCA(cfg config.Config) (*network.CA, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	caDir := filepath.Join(home, ".local", "share", "keel", "ca")
	return network.LoadOrCreateCA(network.CAOptions{
		Dir:  caDir,
		Name: cfg.Network.MITM.CA.Name,
	})
}

func (r HostRunner) prepareVolumes(cfg config.Config, runtimeDir string) ([]vm.AttachedVolume, error) {
	if len(cfg.Volumes) == 0 {
		return nil, nil
	}
	preparer := r.VolumePreparer
	if preparer == nil {
		preparer = volume.PrepareImage
	}
	items := make([]vm.AttachedVolume, 0, len(cfg.Volumes))
	for i, item := range cfg.Volumes {
		imagePath := filepath.Join(runtimeDir, fmt.Sprintf("volume-%02d.ext4", i))
		result, err := preparer(volume.PrepareOptions{
			SourcePath: item.Source,
			ImagePath:  imagePath,
			SizeMB:     max(cfg.Resources.DiskMB, 64),
			Label:      fmt.Sprintf("volume%d", i),
		})
		if err != nil {
			return nil, err
		}
		items = append(items, vm.AttachedVolume{
			ID:         fmt.Sprintf("volume-%02d", i),
			ImagePath:  result.ImagePath,
			DevicePath: vm.GuestBlockDevicePath(i + 2),
			SourcePath: item.Source,
			Target:     item.Target,
			Kind:       result.Kind,
			Subpath:    result.Subpath,
			ReadOnly:   item.ReadOnly,
			SyncBack:   item.SyncBack,
			Ownership:  item.Ownership,
		})
	}
	return items, nil
}

func buildBootManifest(cfg config.Config, volumes []vm.AttachedVolume) pkgboot.Manifest {
	manifest := pkgboot.Manifest{
		Command: append([]string(nil), cfg.Command...),
		CWD:     cfg.Workspace.Target,
		Env:     cloneStringMap(cfg.RuntimeEnv),
	}
	if manifest.CWD == "" {
		manifest.CWD = "/workspace"
	}
	if cfg.Process != nil {
		manifest.Process = &pkgboot.ProcessConfig{
			UID:               cfg.Process.UID,
			GID:               cfg.Process.GID,
			SupplementaryGIDs: append([]int(nil), cfg.Process.SupplementaryGIDs...),
		}
	}
	for _, item := range volumes {
		manifest.Volumes = append(manifest.Volumes, pkgboot.VolumeMount{
			Device:    item.DevicePath,
			Target:    item.Target,
			Kind:      item.Kind,
			Subpath:   item.Subpath,
			ReadOnly:  item.ReadOnly,
			SyncBack:  item.SyncBack,
			Ownership: item.Ownership,
		})
	}
	return manifest
}

func cloneStringMap(items map[string]string) map[string]string {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]string, len(items))
	for key, value := range items {
		out[key] = value
	}
	return out
}

func (r HostRunner) syncWorkspace(req RunRequest, assets vm.RuntimeAssets) error {
	if req.Config.Workspace.SyncBack {
		syncWorkspace := r.SyncWorkspace
		if syncWorkspace == nil {
			syncWorkspace = workspace.SyncImage
		}
		hostDir := req.Config.Workspace.Mount
		if hostDir == "" {
			hostDir = "."
		}
		if _, err := syncWorkspace(workspace.ImageSyncOptions{
			HostDir:     hostDir,
			ImagePath:   assets.WorkspacePath,
			SyncDeletes: req.Config.Workspace.SyncDeletes,
			Confirm:     req.Config.Workspace.SyncConfirm,
			In:          req.Stdin,
			Out:         req.Stderr,
		}); err != nil {
			return err
		}
	}
	syncVolume := r.SyncVolume
	if syncVolume == nil {
		syncVolume = volume.SyncImage
	}
	for _, item := range assets.Volumes {
		if !item.SyncBack || item.ReadOnly {
			continue
		}
		if err := syncVolume(volume.SyncOptions{
			SourcePath: item.SourcePath,
			ImagePath:  item.ImagePath,
			Kind:       item.Kind,
			Subpath:    item.Subpath,
		}); err != nil {
			return err
		}
	}
	return nil
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
		assets.MetadataPath,
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
	for _, item := range assets.Volumes {
		_ = os.RemoveAll(item.ImagePath)
	}
}
