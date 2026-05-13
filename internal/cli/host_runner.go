package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"golang.org/x/sys/unix"

	bootmeta "github.com/moolen/keel/internal/bootmanifest"
	"github.com/moolen/keel/internal/config"
	keelfeatures "github.com/moolen/keel/internal/features"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/network"
	"github.com/moolen/keel/internal/paths"
	keelpty "github.com/moolen/keel/internal/pty"
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
	return paths.NewRuntimeDataDir()
}

func (r HostRunner) controlDir() (string, error) {
	if r.RuntimeDir != "" {
		return r.RuntimeDir, nil
	}
	return paths.NewRuntimeControlDir()
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
	stopServices, summary, err := r.startVMServices(ctx, req.Config, instance)
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
		ensureKernel = manager.EnsureConfig
	}
	progress.Step(startupPhase(3, "ensuring kernel", "resolving guest kernel image"))
	kernelPath, err := ensureKernel(ctx, cfg.Kernel)
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
	cacheReady, err := image.CacheReady(layout, false)
	if err != nil && !os.IsNotExist(err) {
		return vm.RuntimeAssets{}, err
	}
	_, rootfsErr := os.Stat(layout.RootfsPath)
	_, ociErr := os.Stat(layout.OCIPath)
	needsRefresh := !cacheReady && ociErr == nil
	switch {
	case os.IsNotExist(rootfsErr) || needsRefresh:
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
	case rootfsErr != nil:
		return vm.RuntimeAssets{}, rootfsErr
	default:
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
	runtimeDir, err := r.runtimeDir()
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return vm.RuntimeAssets{}, err
	}
	controlDir, err := r.controlDir()
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	if err := os.MkdirAll(controlDir, 0o755); err != nil {
		return vm.RuntimeAssets{}, err
	}
	runtimeRootfsPath := filepath.Join(runtimeDir, "rootfs.ext4")
	workspacePath := filepath.Join(runtimeDir, "workspace.ext4")
	assets := vm.RuntimeAssets{
		KernelPath:    kernelPath,
		RootfsPath:    runtimeRootfsPath,
		WorkspacePath: workspacePath,
		MetadataPath:  filepath.Join(runtimeDir, "bootmeta.ext4"),
		SocketPath:    filepath.Join(controlDir, "firecracker.sock"),
		VSockPath:     filepath.Join(controlDir, "firecracker.vsock"),
		LogPath:       filepath.Join(runtimeDir, "logs", "firecracker.log"),
		RuntimeDir:    runtimeDir,
		ControlDir:    controlDir,
		CleanupDir:    r.RuntimeDir == "",
		CID:           52,
	}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			r.cleanupRuntimeAssets(assets)
		}
	}()

	if r.RuntimeDir == "" || r.RuntimeFreeBytes != nil {
		if err := ensureRuntimeCapacity(runtimeDir, layout.RootfsPath, cfg, r.runtimeFreeBytes); err != nil {
			return vm.RuntimeAssets{}, err
		}
	}
	if err := copyRuntimeRootfs(layout.RootfsPath, runtimeRootfsPath); err != nil {
		return vm.RuntimeAssets{}, err
	}
	if err := ensureRuntimeRootfsSize(runtimeRootfsPath, cfg.Resources.RootDiskMB); err != nil {
		return vm.RuntimeAssets{}, err
	}
	if len(guestAssets.Binary) > 0 {
		if _, err := image.EnsureGuestAgent(runtimeRootfsPath, layout.AgentPath, guestAssets); err != nil {
			return vm.RuntimeAssets{}, err
		}
	}
	if err := image.InjectGuestTrust(runtimeRootfsPath, guestTrust); err != nil {
		return vm.RuntimeAssets{}, err
	}
	if err := r.prepareFeatures(runtimeRootfsPath, cfg.Features); err != nil {
		return vm.RuntimeAssets{}, err
	}

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

func copyRuntimeRootfs(sourcePath, runtimePath string) error {
	src, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open cached rootfs: %w", err)
	}
	defer func() {
		_ = src.Close()
	}()
	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat cached rootfs: %w", err)
	}
	if err := os.Remove(runtimePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove runtime rootfs: %w", err)
	}
	dst, err := os.OpenFile(runtimePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("create runtime rootfs: %w", err)
	}
	defer func() {
		_ = dst.Close()
	}()
	if err := copySparseFile(dst, src, info.Size()); err != nil {
		return fmt.Errorf("copy runtime rootfs: %w", err)
	}
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("sync runtime rootfs: %w", err)
	}
	return nil
}

func (r HostRunner) runtimeFreeBytes(path string) (uint64, error) {
	if r.RuntimeFreeBytes != nil {
		return r.RuntimeFreeBytes(path)
	}
	return runtimeFreeBytes(path)
}

func ensureRuntimeCapacity(runtimeDir, cachedRootfsPath string, cfg config.Config, freeBytes func(string) (uint64, error)) error {
	required, err := estimateRuntimeDataRequirement(cachedRootfsPath, cfg)
	if err != nil {
		return err
	}
	available, err := freeBytes(runtimeDir)
	if err != nil {
		return fmt.Errorf("check runtime free space: %w", err)
	}
	if available >= required {
		return nil
	}
	return fmt.Errorf(
		"insufficient free space for runtime data in %s: need at least %s, have %s; reduce root_disk_mb/resources.disk_mb, free disk space, or move the runtime data root",
		runtimeDir,
		formatBytes(int64(required)),
		formatBytes(int64(available)),
	)
}

func estimateRuntimeDataRequirement(cachedRootfsPath string, cfg config.Config) (uint64, error) {
	rootfsInfo, err := os.Stat(cachedRootfsPath)
	if err != nil {
		return 0, fmt.Errorf("stat cached rootfs: %w", err)
	}

	required := uint64(rootfsInfo.Size())
	if target := uint64(cfg.Resources.RootDiskMB) * 1024 * 1024; target > required {
		required = target
	}
	required += uint64(max(cfg.Resources.DiskMB, 64)) * 1024 * 1024
	required += uint64(len(cfg.Volumes)) * uint64(max(cfg.Resources.DiskMB, 64)) * 1024 * 1024
	required += 256 * 1024 * 1024
	return required, nil
}

func runtimeFreeBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func copySparseFile(dst, src *os.File, size int64) error {
	const chunkSize = 4 << 20

	if size == 0 {
		return nil
	}
	if err := dst.Truncate(size); err != nil {
		return err
	}
	if err := copySparseExtents(dst, src, size, chunkSize); err == nil {
		return nil
	} else if !isSparseSeekUnsupported(err) {
		return err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := dst.Truncate(0); err != nil {
		return err
	}
	_, err := io.CopyBuffer(dst, src, make([]byte, chunkSize))
	return err
}

func copySparseExtents(dst, src *os.File, size int64, chunkSize int) error {
	buf := make([]byte, chunkSize)
	offset := int64(0)
	for offset < size {
		dataOffset, err := unix.Seek(int(src.Fd()), offset, unix.SEEK_DATA)
		switch err {
		case nil:
		case unix.ENXIO:
			return nil
		default:
			return err
		}
		if dataOffset >= size {
			return nil
		}
		holeOffset, err := unix.Seek(int(src.Fd()), dataOffset, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		if holeOffset > size {
			holeOffset = size
		}
		remaining := holeOffset - dataOffset
		if _, err := src.Seek(dataOffset, io.SeekStart); err != nil {
			return err
		}
		if _, err := dst.Seek(dataOffset, io.SeekStart); err != nil {
			return err
		}
		for remaining > 0 {
			chunk := int64(len(buf))
			if remaining < chunk {
				chunk = remaining
			}
			n := int(chunk)
			if _, err := io.ReadFull(src, buf[:n]); err != nil {
				return err
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
			remaining -= chunk
		}
		offset = holeOffset
	}
	return nil
}

func isSparseSeekUnsupported(err error) bool {
	return err == unix.ENXIO || err == unix.EINVAL || err == unix.ENOTSUP || err == unix.ENOSYS || err == unix.EOPNOTSUPP
}

func ensureRuntimeRootfsSize(imagePath string, minSizeMB int) error {
	if minSizeMB <= 0 {
		return nil
	}
	info, err := os.Stat(imagePath)
	if err != nil {
		return fmt.Errorf("stat runtime rootfs: %w", err)
	}
	targetBytes := int64(minSizeMB) * 1024 * 1024
	if info.Size() >= targetBytes {
		return nil
	}
	if err := exec.CommandContext(context.Background(), "truncate", "-s", fmt.Sprintf("%dM", minSizeMB), imagePath).Run(); err != nil {
		return fmt.Errorf("grow runtime rootfs image: %w", err)
	}
	if output, err := exec.CommandContext(context.Background(), "resize2fs", imagePath).CombinedOutput(); err != nil {
		return fmt.Errorf("resize runtime rootfs filesystem: %w: %s", err, output)
	}
	return nil
}

func guestTrustAssetsForConfig(cfg config.Config) (image.GuestTrustAssets, error) {
	policyCfg := network.PolicyConfig{Endpoints: endpointRulesFromConfig(cfg.Network.Endpoints, cfg.Network.Audit)}
	if !policyRequiresMITM(policyCfg) || !cfg.Network.MITM.CA.InstallSystem {
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
	policyCfg := network.PolicyConfig{Endpoints: endpointRulesFromConfig(cfg.Network.Endpoints, cfg.Network.Audit)}
	if !policyRequiresMITM(policyCfg) || !cfg.Network.MITM.CA.InstallDocker {
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
	policyCfg := network.PolicyConfig{
		Audit:     cfg.Network.Audit,
		Endpoints: endpointRulesFromConfig(cfg.Network.Endpoints, cfg.Network.Audit),
		IPRules:   ipRulesFromConfig(cfg.Network.IPRules),
	}
	engine := network.NewPolicyEngine(policyCfg, tracker)
	dnsProxy := network.DNSProxy{
		Policy:  engine,
		Summary: summary,
		Events:  events,
	}
	tcpProxy := network.TCPProxy{
		Policy:  engine,
		Summary: summary,
		Events:  events,
	}
	if policyRequiresMITM(policyCfg) {
		ca, err := loadMITMCA(cfg)
		if err != nil {
			return network.DNSProxy{}, network.TCPProxy{}, nil, err
		}
		tcpProxy.MITM = &network.MITMProxy{
			Enabled: true,
			CA:      ca,
			Summary: summary,
		}
	}
	return dnsProxy, tcpProxy, summary, nil
}

func endpointRulesFromConfig(items []config.EndpointConfig, audit bool) []network.EndpointRule {
	rules := make([]network.EndpointRule, 0, len(items))
	for _, item := range items {
		rule := network.EndpointRule{
			Host:            item.Host,
			Port:            item.Port,
			RequireSNIMatch: true,
		}
		if item.TLS != nil {
			rule.RequireSNIMatch = item.TLS.RequireSNIMatch
		}
		if item.MITM != nil {
			rule.MITMRequired = item.MITM.Required
		}
		if item.HTTP != nil {
			rule.HTTP = endpointHTTPPolicyFromConfig(item.Host, *item.HTTP, audit)
		}
		rules = append(rules, rule)
	}
	return rules
}

func endpointHTTPPolicyFromConfig(host string, item config.EndpointHTTPConfig, audit bool) network.HTTPPolicyConfig {
	return network.HTTPPolicyConfig{
		ScopeHost: host,
		Enabled:   true,
		Default:   item.Default,
		Rules:     endpointHTTPRulesFromConfig(item.Rules),
		Audit:     audit,
	}
}

func endpointHTTPRulesFromConfig(items []config.EndpointHTTPRuleConfig) []network.HTTPRule {
	rules := make([]network.HTTPRule, 0, len(items))
	for _, item := range items {
		rules = append(rules, network.HTTPRule{
			Action:  item.Action,
			Methods: append([]string(nil), item.Methods...),
			Paths:   append([]string(nil), item.Paths...),
		})
	}
	return rules
}

func ipRulesFromConfig(items []config.IPRuleConfig) []network.IPRule {
	rules := make([]network.IPRule, 0, len(items))
	for _, item := range items {
		rules = append(rules, network.IPRule{CIDR: item.CIDR, Port: item.Port})
	}
	return rules
}

func policyRequiresMITM(cfg network.PolicyConfig) bool {
	for _, endpoint := range cfg.Endpoints {
		if endpoint.MITMRequired {
			return true
		}
	}
	return false
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
