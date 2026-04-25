package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/workspace"
)

type machineRunner interface {
	Run(context.Context) error
}

type HostRunner struct {
	RuntimeDir        string
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
	factory := r.MachineFactory
	if factory == nil {
		factory = func(cfg config.Config, assets vm.RuntimeAssets) machineRunner {
			return vm.NewMachine(cfg, assets)
		}
	}
	machine := factory(req.Config, assets)
	return machine.Run(ctx)
}

func (r HostRunner) prepareAssets(ctx context.Context, cfg config.Config) (vm.RuntimeAssets, error) {
	layout, err := image.ResolveCacheLayout(cfg.ImageCacheDir, cfg.Image)
	if err != nil {
		return vm.RuntimeAssets{}, err
	}
	if _, err := os.Stat(layout.RootfsPath); os.IsNotExist(err) {
		pull := r.PullImage
		if pull == nil {
			puller := image.Puller{}
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
		KernelPath:    cfg.Kernel.Path,
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
