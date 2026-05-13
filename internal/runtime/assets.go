package runtime

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	bootmeta "github.com/moolen/keel/internal/bootmanifest"
	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/ext4"
	keelfeatures "github.com/moolen/keel/internal/features"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/network"
	"github.com/moolen/keel/internal/paths"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/volume"
	"github.com/moolen/keel/internal/workspace"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

type Progress interface {
	Step(ProgressStep)
}

type ProgressStep struct {
	Index   int
	Total   int
	Title   string
	Detail  string
	Current int64
	Target  int64
	Done    bool
}

type NopProgress struct{}

func (NopProgress) Step(ProgressStep) {}

type AssetPreparer struct {
	RuntimeDir        string
	RuntimeFreeBytes  func(string) (uint64, error)
	EnsureKernel      func(context.Context, config.KernelConfig) (string, error)
	GuestAssets       func() (image.GuestAgentAssets, error)
	WorkspacePreparer func(workspace.PrepareOptions) (workspace.PrepareResult, error)
	VolumePreparer    func(volume.PrepareOptions) (volume.PrepareResult, error)
	WriteBootManifest func(string, pkgboot.Manifest) error
	PullImage         func(context.Context, string, string) (image.PullResult, error)
	PrepareFeatures   func(string, []config.FeatureConfig) error
}

type SyncRequest struct {
	Config        config.Config
	Stdin         io.Reader
	Stderr        io.Writer
	SyncWorkspace func(workspace.ImageSyncOptions) (workspace.SyncResult, error)
	SyncVolume    func(volume.SyncOptions) error
}

const startupPhaseTotal = 10

func (p AssetPreparer) Prepare(ctx context.Context, cfg config.Config, progress Progress) (vm.RuntimeAssets, error) {
	if progress == nil {
		progress = NopProgress{}
	}
	ensureKernel := p.EnsureKernel
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
	cacheReady, err := image.CacheReady(layout, false)
	if err != nil && !os.IsNotExist(err) {
		return vm.RuntimeAssets{}, err
	}
	_, rootfsErr := os.Stat(layout.RootfsPath)
	_, ociErr := os.Stat(layout.OCIPath)
	needsRefresh := !cacheReady && ociErr == nil
	switch {
	case os.IsNotExist(rootfsErr) || needsRefresh:
		pull := p.PullImage
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
	loadGuestAssets := p.GuestAssets
	if loadGuestAssets == nil {
		loadGuestAssets = defaultGuestAgentAssets
	}
	progress.Step(startupPhase(5, "preparing guest assets", "injecting guest binaries, trust, and rootfs features"))
	guestAssets, err := loadGuestAssets()
	if err != nil {
		return vm.RuntimeAssets{}, fmt.Errorf("load guest assets: %w", err)
	}
	runtimeDir, err := p.runtimeDir()
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return vm.RuntimeAssets{}, err
	}
	controlDir, err := p.controlDir()
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
		CleanupDir:    p.RuntimeDir == "",
		CID:           52,
	}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			CleanupRuntimeAssets(assets)
		}
	}()

	if p.RuntimeDir == "" || p.RuntimeFreeBytes != nil {
		if err := ensureRuntimeCapacity(runtimeDir, layout.RootfsPath, cfg, p.runtimeFreeBytes); err != nil {
			return vm.RuntimeAssets{}, err
		}
	}
	if err := ext4.CopySparseFile(layout.RootfsPath, runtimeRootfsPath); err != nil {
		return vm.RuntimeAssets{}, fmt.Errorf("copy runtime rootfs: %w", err)
	}
	if err := ext4.GrowImage(runtimeRootfsPath, cfg.Resources.RootDiskMB); err != nil {
		return vm.RuntimeAssets{}, fmt.Errorf("ensure runtime rootfs size: %w", err)
	}
	if len(guestAssets.Binary) > 0 {
		if _, err := image.EnsureGuestAgent(runtimeRootfsPath, layout.AgentPath, guestAssets); err != nil {
			return vm.RuntimeAssets{}, err
		}
	}
	if err := image.InjectGuestTrust(runtimeRootfsPath, guestTrust); err != nil {
		return vm.RuntimeAssets{}, err
	}
	if err := p.prepareFeatures(runtimeRootfsPath, cfg.Features); err != nil {
		return vm.RuntimeAssets{}, err
	}

	preparer := p.WorkspacePreparer
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
		SizeMB:     maxInt(cfg.Resources.DiskMB, 64),
		Label:      "workspace",
		Mountpoint: cfg.Workspace.Target,
	}); err != nil {
		return vm.RuntimeAssets{}, err
	}
	progress.Step(startupPhase(7, "preparing extra volumes", "materializing additional writable and read-only volumes"))
	volumes, err := p.prepareVolumes(cfg, runtimeDir)
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	assets.Volumes = volumes
	assets.Manifest = buildBootManifest(cfg, volumes)
	writeBootManifest := p.WriteBootManifest
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

func (p AssetPreparer) Sync(req SyncRequest, assets vm.RuntimeAssets) error {
	if req.Config.Workspace.SyncBack {
		syncWorkspace := req.SyncWorkspace
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
	syncVolume := req.SyncVolume
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

func startupPhase(index int, title, detail string) ProgressStep {
	return ProgressStep{
		Index:  index,
		Total:  startupPhaseTotal,
		Title:  title,
		Detail: detail,
	}
}

func (s ProgressStep) WithProgress(current, target int64, detail string) ProgressStep {
	s.Current = current
	s.Target = target
	if strings.TrimSpace(detail) != "" {
		s.Detail = detail
	}
	return s
}

func (s ProgressStep) Complete(detail string) ProgressStep {
	s.Done = true
	return s.WithProgress(1, 1, detail)
}

func kernelProgressStep(update vm.KernelProgress) ProgressStep {
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

func imagePullProgressStep(update image.PullProgress) ProgressStep {
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

func (p AssetPreparer) runtimeDir() (string, error) {
	if p.RuntimeDir != "" {
		return p.RuntimeDir, nil
	}
	return paths.NewRuntimeDataDir()
}

func (p AssetPreparer) controlDir() (string, error) {
	if p.RuntimeDir != "" {
		return p.RuntimeDir, nil
	}
	return paths.NewRuntimeControlDir()
}

func (p AssetPreparer) runtimeFreeBytes(path string) (uint64, error) {
	if p.RuntimeFreeBytes != nil {
		return p.RuntimeFreeBytes(path)
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
	required += uint64(maxInt(cfg.Resources.DiskMB, 64)) * 1024 * 1024
	required += uint64(len(cfg.Volumes)) * uint64(maxInt(cfg.Resources.DiskMB, 64)) * 1024 * 1024
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

func (p AssetPreparer) prepareVolumes(cfg config.Config, runtimeDir string) ([]vm.AttachedVolume, error) {
	if len(cfg.Volumes) == 0 {
		return nil, nil
	}
	preparer := p.VolumePreparer
	if preparer == nil {
		preparer = volume.PrepareImage
	}
	items := make([]vm.AttachedVolume, 0, len(cfg.Volumes))
	for i, item := range cfg.Volumes {
		imagePath := filepath.Join(runtimeDir, fmt.Sprintf("volume-%02d.ext4", i))
		result, err := preparer(volume.PrepareOptions{
			SourcePath: item.Source,
			ImagePath:  imagePath,
			SizeMB:     maxInt(cfg.Resources.DiskMB, 64),
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

func (p AssetPreparer) prepareFeatures(rootfsPath string, configured []config.FeatureConfig) error {
	if len(configured) == 0 {
		return nil
	}
	prepare := p.PrepareFeatures
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

func defaultGuestAgentAssets() (image.GuestAgentAssets, error) {
	execPath, err := os.Executable()
	if err != nil {
		return image.GuestAgentAssets{}, err
	}
	return loadGuestAgentAssets(execPath, os.ReadFile)
}

func loadGuestAgentAssets(execPath string, readFile func(string) ([]byte, error)) (image.GuestAgentAssets, error) {
	candidates := []string{
		filepath.Join(filepath.Dir(execPath), "..", "dist", "keel-agent"),
		filepath.Join(filepath.Dir(execPath), "dist", "keel-agent"),
	}
	for _, candidate := range candidates {
		data, err := readFile(candidate)
		if err == nil {
			return image.GuestAgentAssets{
				Binary:     data,
				InitScript: "#!/bin/sh\nexec /usr/local/bin/keel-agent\n",
			}, nil
		}
		if !os.IsNotExist(err) {
			return image.GuestAgentAssets{}, err
		}
	}
	return image.GuestAgentAssets{}, fmt.Errorf(
		"guest agent binary not found; looked in %s. build it with `make guest-agent` before pulling or running images",
		strings.Join(candidates, ", "),
	)
}

func CleanupRuntimeAssets(assets vm.RuntimeAssets) {
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func formatBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	value := float64(size)
	suffixes := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, suffix := range suffixes {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f PiB", value/unit)
}
