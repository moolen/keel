package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/network"
	keelpty "github.com/moolen/keel/internal/pty"
	keelruntime "github.com/moolen/keel/internal/runtime"
	"github.com/moolen/keel/internal/runtimeenv"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/volume"
	"github.com/moolen/keel/internal/workspace"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

type machineRunner interface {
	Run(context.Context) error
}

type HostRunner struct {
	RuntimeDir        string
	RuntimeFreeBytes  func(string) (uint64, error)
	EnsureKernel      func(context.Context, config.KernelConfig) (string, error)
	GuestAssets       func() (image.GuestAgentAssets, error)
	WorkspacePreparer func(workspace.PrepareOptions) (workspace.PrepareResult, error)
	SyncWorkspace     func(workspace.ImageSyncOptions) (workspace.SyncResult, error)
	VolumePreparer    func(volume.PrepareOptions) (volume.PrepareResult, error)
	SyncVolume        func(volume.SyncOptions) error
	ResolveEnv        func(config.EnvConfig) (map[string]string, error)
	WriteBootManifest func(string, pkgboot.Manifest) error
	PullImage         func(context.Context, string, string) (image.PullResult, error)
	PrepareAssets     func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error)
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
	factory := r.MachineFactory
	if factory != nil {
		startServices := r.ServiceStarter
		if startServices == nil {
			startServices = defaultNetworkServiceStarter
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
		r.warnNetworkAuditMode(req)
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
	stopServices, summary, err := keelruntime.NetworkServiceFactory{}.StartVM(ctx, req.Config, instance)
	if err != nil {
		return err
	}
	defer stopServices()
	defer r.printNetworkSummary(req, summary)

	progress.Step(startupPhase(10, "booting vm and attaching terminal", "handing off to guest process"))
	progress.Stop()
	r.warnNetworkAuditMode(req)
	if err := machine.EnsureKVMAccess(); err != nil {
		return err
	}
	if err := instance.Start(ctx); err != nil {
		return err
	}
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
	return newStartupProgressReporter(output, startupProgressOptions{
		DryRun:      req.Config.DryRun,
		Interactive: r.ProgressEnabled,
		Factory:     r.ProgressFactory,
	})
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

func defaultNetworkServiceStarter(ctx context.Context, cfg config.Config, assets vm.RuntimeAssets) (func(), *network.Summary, error) {
	stop, summary, err := (keelruntime.NetworkServiceFactory{}).StartUnix(ctx, cfg, assets)
	if stop == nil {
		return nil, summary, err
	}
	return func() { stop() }, summary, err
}

func (r HostRunner) prepareAssets(ctx context.Context, cfg config.Config, progress progressReporter) (vm.RuntimeAssets, error) {
	assetProgress := cliRuntimeProgress{reporter: progress}
	if r.PrepareAssets != nil {
		return r.PrepareAssets(ctx, cfg, assetProgress)
	}
	preparer := keelruntime.AssetPreparer{
		RuntimeDir:        r.RuntimeDir,
		RuntimeFreeBytes:  r.RuntimeFreeBytes,
		EnsureKernel:      r.EnsureKernel,
		GuestAssets:       r.GuestAssets,
		WorkspacePreparer: r.WorkspacePreparer,
		VolumePreparer:    r.VolumePreparer,
		WriteBootManifest: r.WriteBootManifest,
		PullImage:         r.PullImage,
		PrepareFeatures:   r.PrepareFeatures,
	}
	return preparer.Prepare(ctx, cfg, assetProgress)
}

type cliRuntimeProgress struct {
	reporter progressReporter
}

func (p cliRuntimeProgress) Step(step keelruntime.ProgressStep) {
	if p.reporter == nil {
		return
	}
	p.reporter.Step(startupStep{
		Index:   step.Index,
		Total:   step.Total,
		Title:   step.Title,
		Detail:  step.Detail,
		Current: step.Current,
		Target:  step.Target,
	})
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
	if !cfg.Network.MITM.CA.InstallDocker {
		return features, nil
	}
	services, err := (keelruntime.NetworkServiceFactory{}).Build(cfg)
	if err != nil {
		return nil, err
	}
	if services.TCP.MITM == nil || services.TCP.MITM.CA == nil {
		return features, nil
	}
	for i := range features {
		if features[i].Name != "docker" {
			continue
		}
		cloned := map[string]any{}
		for key, value := range features[i].Config {
			cloned[key] = value
		}
		cloned["mitm_ca_pem"] = string(services.TCP.MITM.CA.CertPEM)
		features[i].Config = cloned
	}
	return features, nil
}

func (r HostRunner) syncWorkspace(req RunRequest, assets vm.RuntimeAssets) error {
	return (keelruntime.AssetPreparer{}).Sync(keelruntime.SyncRequest{
		Config:        req.Config,
		Stdin:         req.Stdin,
		Stderr:        req.Stderr,
		SyncWorkspace: r.SyncWorkspace,
		SyncVolume:    r.SyncVolume,
	}, assets)
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
		if assets.ControlDir != "" && assets.ControlDir != assets.RuntimeDir {
			_ = os.RemoveAll(assets.ControlDir)
		}
		return
	}
	for _, path := range []string{
		assets.RootfsPath,
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
