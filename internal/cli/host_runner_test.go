package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/image"
	"github.com/moolen/keel/internal/network"
	keelruntime "github.com/moolen/keel/internal/runtime"
	"github.com/moolen/keel/internal/vm"
	"github.com/moolen/keel/internal/vsock"
	"github.com/moolen/keel/internal/workspace"
)

func TestHostRunnerDryRunPrintsSummary(t *testing.T) {
	var stdout bytes.Buffer
	runner := HostRunner{}
	cfg := config.Default()
	cfg.Image = "debian:bookworm"
	cfg.DryRun = true

	err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh", "-lc", "echo hello"},
		Stdout:  &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "dry-run") || !strings.Contains(output, "debian:bookworm") {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestHostRunnerDryRunDoesNotValidateFeatureRegistry(t *testing.T) {
	var stdout bytes.Buffer
	runner := HostRunner{}
	cfg := config.Default()
	cfg.DryRun = true
	cfg.Features = []config.FeatureConfig{{
		Name: "future-feature",
		Config: map[string]any{
			"enabled": true,
		},
	}}

	if err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh"},
		Stdout:  &stdout,
	}); err != nil {
		t.Fatalf("Run() error = %v, want dry-run summary without feature registry validation", err)
	}
	if !strings.Contains(stdout.String(), "dry-run") {
		t.Fatalf("dry-run output = %q, want summary", stdout.String())
	}
}

func TestForwardedPTYStdinSkipsNonTerminalWhenSyncConfirmEnabled(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()

	cfg := config.Default()
	cfg.Workspace.SyncConfirm = true
	if got := forwardedPTYStdin(RunRequest{Config: cfg, Stdin: stdin}); got != nil {
		t.Fatalf("forwardedPTYStdin() = %v, want nil", got)
	}
}

func TestForwardedPTYStdinAllowsNonTerminalWithoutSyncConfirm(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()

	cfg := config.Default()
	cfg.Workspace.SyncConfirm = false
	if got := forwardedPTYStdin(RunRequest{Config: cfg, Stdin: stdin}); got != stdin {
		t.Fatalf("forwardedPTYStdin() = %v, want %v", got, stdin)
	}
}

func TestRunPreparedVMLeavesPipedInputForSyncConfirmation(t *testing.T) {
	tempDir := t.TempDir()
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()
	if _, err := stdin.WriteString("y\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if _, err := stdin.Seek(0, 0); err != nil {
		t.Fatalf("Seek() error = %v", err)
	}

	cfg := config.Default()
	cfg.Network.Mode = "none"
	cfg.Workspace.SyncBack = true
	cfg.Workspace.SyncConfirm = true

	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)
	vmInstance := &capturePTYInputVM{}
	machine := vm.NewMachine(cfg, assets)
	machine.NewVM = func(hypervisor.Config) (hypervisor.VM, error) {
		return vmInstance, nil
	}

	var stdout bytes.Buffer
	var syncInput string
	runner := HostRunner{
		SyncWorkspace: func(opts workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			data, err := io.ReadAll(opts.In)
			if err != nil {
				return workspace.SyncResult{}, err
			}
			syncInput = string(data)
			return workspace.SyncResult{Applied: true}, nil
		},
	}

	req := RunRequest{
		Config: cfg,
		Stdin:  stdin,
		Stdout: &stdout,
	}
	if err := runner.runPreparedVM(context.Background(), req, machine, nopProgressReporter{}); err != nil {
		t.Fatalf("runPreparedVM() error = %v", err)
	}
	if err := runner.syncWorkspace(req, assets); err != nil {
		t.Fatalf("syncWorkspace() error = %v", err)
	}
	if got := vmInstance.Input(); got != "" {
		t.Fatalf("PTY input = %q, want empty", got)
	}
	if got, want := syncInput, "y\n"; got != want {
		t.Fatalf("sync input = %q, want %q", got, want)
	}
}

func TestRunPreparedVMRechecksKVMAccessBeforeStart(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Network.Mode = "none"

	var kvmChecks int
	instance := &stubHypervisorVM{
		start: func(context.Context) error {
			if kvmChecks != 2 {
				t.Fatalf("kvm checks before Start = %d, want 2", kvmChecks)
			}
			return nil
		},
		listen: func(port uint32) (net.Listener, error) {
			return (&net.ListenConfig{}).Listen(context.Background(), "unix", filepath.Join(t.TempDir(), "vsock-"+strconv.Itoa(int(port))))
		},
	}
	machine := vm.NewMachine(cfg, runtimeAssetsForHostRunnerVMTest(t, tempDir))
	machine.EnsureKVMAccessFunc = func() error {
		kvmChecks++
		return nil
	}
	machine.NewVM = func(hypervisor.Config) (hypervisor.VM, error) {
		return instance, nil
	}
	machine.AttachPTY = func(context.Context, hypervisor.VM) error {
		return nil
	}

	runner := HostRunner{}
	req := RunRequest{Config: cfg}
	if err := runner.runPreparedVM(context.Background(), req, machine, nopProgressReporter{}); err != nil {
		t.Fatalf("runPreparedVM() error = %v", err)
	}
}

func TestHostRunnerPreparesAssetsBeforeLaunch(t *testing.T) {
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.Workspace.Target = "/workspace"

	preparedAssets := vm.RuntimeAssets{
		KernelPath:    "/prepared/vmlinux",
		RootfsPath:    "/prepared/rootfs.ext4",
		WorkspacePath: "/prepared/workspace.ext4",
		MetadataPath:  "/prepared/bootmeta.ext4",
		SocketPath:    "/prepared/firecracker.sock",
		VSockPath:     "/prepared/firecracker.vsock",
		CID:           52,
	}
	var prepared bool
	var machineAssets vm.RuntimeAssets

	runner := HostRunner{
		PrepareAssets: func(_ context.Context, gotCfg config.Config, _ keelruntime.Progress) (vm.RuntimeAssets, error) {
			prepared = true
			if gotCfg.Image != cfg.Image {
				t.Fatalf("PrepareAssets cfg.Image = %q, want %q", gotCfg.Image, cfg.Image)
			}
			return preparedAssets, nil
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			if !prepared {
				t.Fatal("MachineFactory called before PrepareAssets")
			}
			machineAssets = assets
			return stubMachineRunner{}
		},
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			return func() {}, nil, nil
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !prepared {
		t.Fatal("PrepareAssets was not called")
	}
	if !reflect.DeepEqual(machineAssets, preparedAssets) {
		t.Fatalf("machine assets = %#v, want %#v", machineAssets, preparedAssets)
	}
}

func TestHostRunnerDelegatesRuntimePreparationAndNetworkStartup(t *testing.T) {
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.Workspace.Mount = t.TempDir()

	var prepared bool
	var startedServices bool
	var ranMachine bool
	assets := runtimeAssetsForHostRunnerVMTest(t, t.TempDir())

	runner := HostRunner{
		PrepareAssets: func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error) {
			prepared = true
			return assets, nil
		},
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			startedServices = true
			return func() {}, network.NewSummary(), nil
		},
		MachineFactory: func(config.Config, vm.RuntimeAssets) machineRunner {
			return machineRunnerFunc(func(context.Context) error {
				ranMachine = true
				return nil
			})
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !prepared || !startedServices || !ranMachine {
		t.Fatalf("delegation prepared=%v services=%v ran=%v", prepared, startedServices, ranMachine)
	}
}

func TestHostRunnerDoesNotOwnMigratedRuntimeHelpers(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "host_runner.go", nil, 0)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	disallowedFields := map[string]struct{}{
		"RuntimeDir":        {},
		"RuntimeFreeBytes":  {},
		"EnsureKernel":      {},
		"GuestAssets":       {},
		"WorkspacePreparer": {},
		"VolumePreparer":    {},
		"WriteBootManifest": {},
		"PullImage":         {},
		"PrepareFeatures":   {},
	}
	disallowedFunctions := map[string]struct{}{
		"defaultNetworkServiceStarter": {},
		"cleanupRuntimeAssets":         {},
		"kernelProgressStep":           {},
		"imagePullProgressStep":        {},
	}

	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if _, disallowed := disallowedFunctions[fn.Name.Name]; disallowed {
				t.Fatalf("host_runner.go still declares migrated runtime helper function %q", fn.Name.Name)
			}
			continue
		}
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "HostRunner" {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("HostRunner is %T, want struct type", typeSpec.Type)
			}
			for _, field := range structType.Fields.List {
				for _, name := range field.Names {
					if _, disallowed := disallowedFields[name.Name]; disallowed {
						t.Fatalf("HostRunner still exposes migrated runtime helper field %q", name.Name)
					}
				}
			}
		}
	}
}

func TestHostRunnerReturnsWorkspacePrepareError(t *testing.T) {
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"

	runner := HostRunner{
		PrepareAssets: func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error) {
			return vm.RuntimeAssets{}, errors.New("boom")
		},
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Run() error = %v, want propagated workspace failure", err)
	}
}

func TestHostRunnerRuntimeConfigMaterializesEnv(t *testing.T) {
	cfg := config.Default()
	cfg.Env.Static["CI"] = "1"
	cfg.Env.FromHost = map[string]string{
		"TOKEN": "HOST_TOKEN",
	}
	t.Setenv("HOST_TOKEN", "secret")

	runner := HostRunner{
		ResolveEnv: func(env config.EnvConfig) (map[string]string, error) {
			return map[string]string{
				"CI":    env.Static["CI"],
				"TOKEN": "secret",
			}, nil
		},
	}
	runtimeCfg, err := runner.runtimeConfig(cfg)
	if err != nil {
		t.Fatalf("runtimeConfig() error = %v", err)
	}
	if got, want := runtimeCfg.RuntimeEnv["TOKEN"], "secret"; got != want {
		t.Fatalf("runtime env TOKEN = %q, want %q", got, want)
	}
}

func TestHostRunnerRuntimeConfigInjectsDockerMITMCAPEM(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cfg := config.Default()
	cfg.Network.Endpoints = []config.EndpointConfig{{
		Host: "api.github.com",
		Port: 443,
		MITM: &config.EndpointMITMConfig{Required: true},
	}}
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.MITM.CA.InstallDocker = true
	cfg.Features = []config.FeatureConfig{{
		Name:   "docker",
		Config: map[string]any{},
	}}

	runner := HostRunner{}
	runtimeCfg, err := runner.runtimeConfig(cfg)
	if err != nil {
		t.Fatalf("runtimeConfig() error = %v", err)
	}
	if len(runtimeCfg.Features) != 1 {
		t.Fatalf("len(runtimeCfg.Features) = %d, want 1", len(runtimeCfg.Features))
	}
	value, ok := runtimeCfg.Features[0].Config["mitm_ca_pem"].(string)
	if !ok || !strings.Contains(value, "BEGIN CERTIFICATE") {
		t.Fatalf("mitm_ca_pem = %#v, want CA PEM string", runtimeCfg.Features[0].Config["mitm_ca_pem"])
	}
	if got := runtimeCfg.Features[0].Config["storage_driver"]; got != "vfs" {
		t.Fatalf("storage_driver = %#v, want vfs", got)
	}
}

func TestHostRunnerRuntimeConfigNormalizesDockerFeatureForKernelArgs(t *testing.T) {
	cfg := config.Default()
	cfg.Features = []config.FeatureConfig{{
		Name: "docker",
		Config: map[string]any{
			"registry_mirrors": []any{"https://mirror.example"},
		},
	}}

	runtimeCfg, err := (HostRunner{}).runtimeConfig(cfg)
	if err != nil {
		t.Fatalf("runtimeConfig() error = %v", err)
	}
	if len(runtimeCfg.Features) != 1 || runtimeCfg.Features[0].Name != "docker" {
		t.Fatalf("runtime features = %#v", runtimeCfg.Features)
	}
	if got := runtimeCfg.Features[0].Config["storage_driver"]; got != "vfs" {
		t.Fatalf("runtime storage_driver = %#v, want vfs", got)
	}

	machine := vm.NewMachine(runtimeCfg, vm.RuntimeAssets{
		KernelPath:    "/tmp/vmlinux",
		RootfsPath:    "/tmp/rootfs.ext4",
		WorkspacePath: "/tmp/workspace.ext4",
		MetadataPath:  "/tmp/bootmeta.ext4",
		SocketPath:    "/tmp/firecracker.sock",
		VSockPath:     "/tmp/firecracker.vsock",
		LogPath:       "/tmp/firecracker.log",
		CID:           52,
	})
	hvCfg, err := machine.BuildHypervisorConfig()
	if err != nil {
		t.Fatalf("BuildHypervisorConfig() error = %v", err)
	}
	features := decodeKernelArgFeatures(t, hvCfg.KernelArgs)
	if got := features[0].Config["storage_driver"]; got != "vfs" {
		t.Fatalf("kernel storage_driver = %#v, want vfs", got)
	}
	if _, ok := features[0].Config["registry_mirrors"]; !ok {
		t.Fatalf("kernel feature config = %#v, want registry_mirrors", features[0].Config)
	}
}

func TestHostRunnerWarnsWhenNetworkAuditModeIsEnabled(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Network.Audit = true

	var stderr bytes.Buffer
	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	runner := HostRunner{
		PrepareAssets: prepareAssetsHook(assets),
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh"},
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(stderr.String(), "network audit mode enabled") {
		t.Fatalf("stderr = %q, want audit warning", stderr.String())
	}
}

func TestHostRunnerAllocatesUniqueRuntimeDirByDefault(t *testing.T) {
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = t.TempDir()
	cfg.Workspace.Mount = t.TempDir()

	rootfsPath := filepath.Join(cfg.ImageCacheDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var preparePaths []string
	runner := HostRunner{
		PrepareAssets: func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error) {
			runtimeDir := filepath.Join(t.TempDir(), fmt.Sprintf("vm-%d", len(preparePaths)+1))
			if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
				return vm.RuntimeAssets{}, err
			}
			assets := runtimeAssetsForHostRunnerVMTest(t, runtimeDir)
			assets.CleanupDir = true
			preparePaths = append(preparePaths, assets.WorkspacePath)
			return assets, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	for range 2 {
		if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	}
	if len(preparePaths) != 2 {
		t.Fatalf("preparePaths = %d, want 2", len(preparePaths))
	}
	if preparePaths[0] == preparePaths[1] {
		t.Fatalf("workspace paths should differ, got %q", preparePaths[0])
	}
	for _, path := range preparePaths {
		if !strings.HasPrefix(filepath.Base(filepath.Dir(path)), "vm-") {
			t.Fatalf("workspace path = %q, want generated vm directory", path)
		}
	}
}

func TestHostRunnerCleansUpEphemeralRuntimeDir(t *testing.T) {
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = t.TempDir()
	cfg.Workspace.Mount = t.TempDir()

	rootfsPath := filepath.Join(cfg.ImageCacheDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var runtimeDir string
	runner := HostRunner{
		PrepareAssets: func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error) {
			runtimeDir = filepath.Join(t.TempDir(), "vm-ephemeral")
			if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
				return vm.RuntimeAssets{}, err
			}
			assets := runtimeAssetsForHostRunnerVMTest(t, runtimeDir)
			assets.CleanupDir = true
			return assets, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if runtimeDir == "" {
		t.Fatal("runtime dir should be captured")
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir %q should be removed, stat err=%v", runtimeDir, err)
	}
}

func TestHostRunnerRemovesArtifactsFromExplicitRuntimeDir(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	runner := HostRunner{
		PrepareAssets: prepareAssetsHook(assets),
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, err := os.Stat(tempDir); err != nil {
		t.Fatalf("runtime dir %q should remain, stat err=%v", tempDir, err)
	}
	for _, artifact := range []string{
		filepath.Join(tempDir, "rootfs.ext4"),
		filepath.Join(tempDir, "workspace.ext4"),
		filepath.Join(tempDir, "firecracker.sock"),
		filepath.Join(tempDir, "firecracker.vsock"),
		filepath.Join(tempDir, "firecracker.vsock_3053"),
		filepath.Join(tempDir, "firecracker.vsock_3128"),
		filepath.Join(tempDir, "logs", "firecracker.log"),
	} {
		if _, err := os.Stat(artifact); !os.IsNotExist(err) {
			t.Fatalf("artifact %q should be removed, stat err=%v", artifact, err)
		}
	}
}

func TestHostRunnerRemovesArtifactsFromExplicitRuntimeDirWhenRunFails(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	writeCachedRootfsForHostRunnerTest(t, cfg.ImageCacheDir, cfg.Image)
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	runner := HostRunner{
		PrepareAssets: prepareAssetsHook(assets),
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return machineRunnerFunc(func(context.Context) error {
				return errors.New("vm failed")
			})
		},
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}})
	if err == nil || !strings.Contains(err.Error(), "vm failed") {
		t.Fatalf("Run() error = %v, want vm failure", err)
	}
	if _, err := os.Stat(tempDir); err != nil {
		t.Fatalf("runtime dir %q should remain, stat err=%v", tempDir, err)
	}
	for _, artifact := range []string{
		filepath.Join(tempDir, "rootfs.ext4"),
		filepath.Join(tempDir, "workspace.ext4"),
		filepath.Join(tempDir, "bootmeta.ext4"),
		filepath.Join(tempDir, "firecracker.sock"),
		filepath.Join(tempDir, "firecracker.vsock"),
		filepath.Join(tempDir, "logs", "firecracker.log"),
	} {
		if _, err := os.Stat(artifact); !os.IsNotExist(err) {
			t.Fatalf("artifact %q should be removed after failed run, stat err=%v", artifact, err)
		}
	}
}

func TestHostRunnerSyncsWorkspaceAfterCommandExit(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Workspace.SyncBack = true

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	var syncOpts workspace.ImageSyncOptions
	runner := HostRunner{
		PrepareAssets: prepareAssetsHook(assets),
		SyncWorkspace: func(opts workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			syncOpts = opts
			return workspace.SyncResult{Applied: true}, nil
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh"},
		Stdin:   strings.NewReader("y\n"),
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if syncOpts.HostDir != cfg.Workspace.Mount {
		t.Fatalf("sync host dir = %q, want %q", syncOpts.HostDir, cfg.Workspace.Mount)
	}
	if syncOpts.ImagePath == "" {
		t.Fatal("sync image path should not be empty")
	}
	if !syncOpts.Confirm {
		t.Fatal("sync confirm should follow workspace config")
	}
}

func TestHostRunnerPrintsNetworkSummaryAfterShutdown(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	summary := network.NewSummary()
	summary.RecordDNS("api.github.com", network.Decision{Allowed: true})
	summary.RecordTCP("github.com", 443, network.Decision{Allowed: false})

	var stderr bytes.Buffer
	runner := HostRunner{
		PrepareAssets: prepareAssetsHook(assets),
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			return func() {}, summary, nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	if err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh"},
		Stderr:  &stderr,
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	output := stderr.String()
	if !strings.Contains(output, "Network summary:") {
		t.Fatalf("stderr = %q, want network summary header", output)
	}
	if !strings.Contains(output, "dns  api.github.com:53 policy=allowed count=1") {
		t.Fatalf("stderr = %q, want dns summary entry", output)
	}
	if !strings.Contains(output, "tcp  github.com:443 policy=denied count=1") {
		t.Fatalf("stderr = %q, want tcp summary entry", output)
	}
}

func TestHostRunnerStopsVMServicesWhenMachineRunFails(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	writeCachedRootfsForHostRunnerTest(t, cfg.ImageCacheDir, cfg.Image)
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	var stopCalls int
	runner := HostRunner{
		PrepareAssets: prepareAssetsHook(assets),
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			return func() { stopCalls++ }, network.NewSummary(), nil
		},
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return machineRunnerFunc(func(context.Context) error {
				return errors.New("machine failed")
			})
		},
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}})
	if err == nil || !strings.Contains(err.Error(), "machine failed") {
		t.Fatalf("Run() error = %v, want machine failure", err)
	}
	if stopCalls != 1 {
		t.Fatalf("service stop calls = %d, want 1", stopCalls)
	}
}

func TestHostRunnerReportsStartupPhasesInOrderAndStopsBeforeMachineRun(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	var events []string
	reporter := &recordingProgressReporter{
		onStep: func(step startupStep) { events = append(events, step.Title) },
		onStop: func() { events = append(events, "progress-stop") },
	}
	runner := HostRunner{
		PrepareAssets: prepareAssetsHookWithStartupSteps(assets),
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			return func() {}, network.NewSummary(), nil
		},
		ProgressEnabled: func(io.Writer) bool { return true },
		ProgressFactory: func(io.Writer, int) (progressReporter, error) { return reporter, nil },
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return machineRunnerFunc(func(context.Context) error {
				events = append(events, "machine-run")
				return nil
			})
		},
	}

	if err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	wantPhases := []string{
		"resolving config",
		"resolving runtime env",
		"ensuring kernel",
		"pulling oci image",
		"preparing guest assets",
		"preparing workspace image",
		"preparing extra volumes",
		"writing boot metadata image",
		"starting vm services",
		"booting vm and attaching terminal",
		"progress-stop",
		"machine-run",
	}
	if !reflect.DeepEqual(events, wantPhases) {
		t.Fatalf("events = %#v, want %#v", events, wantPhases)
	}
}

func TestHostRunnerStopsProgressBeforeAuditWarningAndMachineRun(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Network.Audit = true

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	var (
		events []string
		stderr bytes.Buffer
	)
	reporter := &recordingProgressReporter{
		onStep: func(step startupStep) { events = append(events, step.Title) },
		onStop: func() { events = append(events, "progress-stop") },
	}
	runner := HostRunner{
		PrepareAssets: prepareAssetsHookWithStartupSteps(assets),
		ServiceStarter: func(context.Context, config.Config, vm.RuntimeAssets) (func(), *network.Summary, error) {
			return func() {}, network.NewSummary(), nil
		},
		ProgressEnabled: func(io.Writer) bool { return true },
		ProgressFactory: func(io.Writer, int) (progressReporter, error) { return reporter, nil },
		MachineFactory: func(_ config.Config, _ vm.RuntimeAssets) machineRunner {
			return machineRunnerFunc(func(context.Context) error {
				events = append(events, "machine-run")
				if got := events[len(events)-2]; got != "progress-stop" {
					return fmt.Errorf("event before machine-run = %q, want progress-stop", got)
				}
				if !strings.Contains(stderr.String(), "warning: network audit mode enabled") {
					return fmt.Errorf("stderr = %q, want audit warning", stderr.String())
				}
				return nil
			})
		},
	}

	err := runner.Run(context.Background(), RunRequest{
		Config:  cfg,
		Command: []string{"/bin/sh"},
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestHostRunnerStopsProgressBeforeReturningStartupError(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var events []string
	reporter := &recordingProgressReporter{
		onStep: func(step startupStep) { events = append(events, step.Title) },
		onStop: func() { events = append(events, "progress-stop") },
	}
	runner := HostRunner{
		PrepareAssets: func(_ context.Context, _ config.Config, progress keelruntime.Progress) (vm.RuntimeAssets, error) {
			for _, step := range runtimePreparationProgressSteps()[:4] {
				progress.Step(step)
			}
			return vm.RuntimeAssets{}, errors.New("workspace exploded")
		},
		ProgressEnabled: func(io.Writer) bool { return true },
		ProgressFactory: func(io.Writer, int) (progressReporter, error) { return reporter, nil },
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}, Stderr: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "workspace exploded") {
		t.Fatalf("Run() error = %v, want workspace error", err)
	}
	wantEvents := []string{
		"resolving config",
		"resolving runtime env",
		"ensuring kernel",
		"pulling oci image",
		"preparing guest assets",
		"preparing workspace image",
		"progress-stop",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestHostRunnerReturnsSyncErrorAfterSuccessfulRun(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Image = "ubuntu:24.04"
	cfg.ImageCacheDir = tempDir
	cfg.Workspace.Mount = t.TempDir()
	cfg.Workspace.SyncBack = true

	rootfsPath := filepath.Join(tempDir, "index.docker.io", "library", "ubuntu", "24.04", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	assets := runtimeAssetsForHostRunnerVMTest(t, tempDir)

	runner := HostRunner{
		PrepareAssets: prepareAssetsHook(assets),
		SyncWorkspace: func(opts workspace.ImageSyncOptions) (workspace.SyncResult, error) {
			return workspace.SyncResult{}, errors.New("sync failed")
		},
		MachineFactory: func(_ config.Config, assets vm.RuntimeAssets) machineRunner {
			return stubMachineRunner{}
		},
	}

	err := runner.Run(context.Background(), RunRequest{Config: cfg, Command: []string{"/bin/sh"}})
	if err == nil || !strings.Contains(err.Error(), "sync failed") {
		t.Fatalf("Run() error = %v, want sync failure", err)
	}
}

type stubMachineRunner struct{}

func (stubMachineRunner) Run(context.Context) error {
	return nil
}

type machineRunnerFunc func(context.Context) error

func (f machineRunnerFunc) Run(ctx context.Context) error {
	return f(ctx)
}

type recordingProgressReporter struct {
	onStep    func(startupStep)
	onStop    func()
	lastTitle string
}

func (r *recordingProgressReporter) Step(step startupStep) {
	if step.Title == r.lastTitle {
		return
	}
	r.lastTitle = step.Title
	if r.onStep != nil {
		r.onStep(step)
	}
}

func (r *recordingProgressReporter) Stop() {
	if r.onStop != nil {
		r.onStop()
	}
}

type stubHypervisorVM struct {
	start         func(context.Context) error
	listen        func(uint32) (net.Listener, error)
	listenedPorts []uint32
}

func (v *stubHypervisorVM) Start(ctx context.Context) error {
	if v.start != nil {
		return v.start(ctx)
	}
	return nil
}
func (*stubHypervisorVM) Stop(context.Context) error { return nil }
func (*stubHypervisorVM) Wait(context.Context) error { return nil }
func (*stubHypervisorVM) VSockConnect(uint32) (net.Conn, error) {
	server, client := net.Pipe()
	go server.Close()
	return client, nil
}

func (v *stubHypervisorVM) VSockListen(port uint32) (net.Listener, error) {
	v.listenedPorts = append(v.listenedPorts, port)
	if v.listen != nil {
		return v.listen(port)
	}
	return nil, nil
}

var _ hypervisor.VM = (*stubHypervisorVM)(nil)

type capturePTYInputVM struct {
	mu    sync.Mutex
	input bytes.Buffer
}

func (*capturePTYInputVM) Start(context.Context) error { return nil }
func (*capturePTYInputVM) Stop(context.Context) error  { return nil }
func (*capturePTYInputVM) Wait(context.Context) error  { return nil }

func (*capturePTYInputVM) VSockListen(port uint32) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(context.Background(), "unix", filepath.Join(os.TempDir(), "keel-vsock-"+strconv.Itoa(int(port))+"-"+strconv.FormatInt(time.Now().UnixNano(), 10)))
}

func (v *capturePTYInputVM) VSockConnect(uint32) (net.Conn, error) {
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		for {
			frame, err := vsock.ReadFrame(server)
			if err != nil {
				break
			}
			if frame.Type == vsock.MessageData {
				v.mu.Lock()
				_, _ = v.input.Write(frame.Data)
				v.mu.Unlock()
			}
		}
		_ = vsock.WriteExitFrame(server, 0)
	}()
	return client, nil
}

func (v *capturePTYInputVM) Input() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.input.String()
}

func prepareAssetsHook(assets vm.RuntimeAssets) func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error) {
	return func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error) {
		return assets, nil
	}
}

func prepareAssetsHookWithStartupSteps(assets vm.RuntimeAssets) func(context.Context, config.Config, keelruntime.Progress) (vm.RuntimeAssets, error) {
	return func(_ context.Context, _ config.Config, progress keelruntime.Progress) (vm.RuntimeAssets, error) {
		for _, step := range runtimePreparationProgressSteps() {
			progress.Step(step)
		}
		return assets, nil
	}
}

func runtimePreparationProgressSteps() []keelruntime.ProgressStep {
	return []keelruntime.ProgressStep{
		{Index: 3, Total: 10, Title: "ensuring kernel", Detail: "resolving guest kernel image"},
		{Index: 4, Total: 10, Title: "pulling oci image", Detail: "resolving cached rootfs and image layers"},
		{Index: 5, Total: 10, Title: "preparing guest assets", Detail: "injecting guest binaries, trust, and rootfs features"},
		{Index: 6, Total: 10, Title: "preparing workspace image", Detail: "copying workspace into an ext4 snapshot"},
		{Index: 7, Total: 10, Title: "preparing extra volumes", Detail: "materializing additional writable and read-only volumes"},
		{Index: 8, Total: 10, Title: "writing boot metadata image", Detail: "packing command, env, process, and volume metadata"},
	}
}

func runtimeAssetsForHostRunnerVMTest(t *testing.T, dir string) vm.RuntimeAssets {
	t.Helper()
	assets := vm.RuntimeAssets{
		KernelPath:    filepath.Join(dir, "vmlinux"),
		RootfsPath:    filepath.Join(dir, "rootfs.ext4"),
		WorkspacePath: filepath.Join(dir, "workspace.ext4"),
		MetadataPath:  filepath.Join(dir, "bootmeta.ext4"),
		SocketPath:    filepath.Join(dir, "firecracker.sock"),
		VSockPath:     filepath.Join(dir, "firecracker.vsock"),
		LogPath:       filepath.Join(dir, "firecracker.log"),
		RuntimeDir:    dir,
		CID:           52,
	}
	for _, path := range []string{assets.KernelPath, assets.RootfsPath, assets.WorkspacePath, assets.MetadataPath} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}
	return assets
}

func decodeKernelArgFeatures(t *testing.T, kernelArgs string) []config.FeatureConfig {
	t.Helper()
	for _, field := range strings.Fields(kernelArgs) {
		if !strings.HasPrefix(field, "keel.features=") {
			continue
		}
		data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(field, "keel.features="))
		if err != nil {
			t.Fatalf("DecodeString() error = %v", err)
		}
		var features []config.FeatureConfig
		if err := json.Unmarshal(data, &features); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		return features
	}
	t.Fatalf("keel.features not found in %q", kernelArgs)
	return nil
}

func writeCachedRootfsForHostRunnerTest(t *testing.T, cacheDir, imageRef string) string {
	t.Helper()
	layout, err := image.ResolveCacheLayout(cacheDir, imageRef)
	if err != nil {
		t.Fatalf("ResolveCacheLayout() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.RootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(layout.RootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return layout.RootfsPath
}
