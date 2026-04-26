package agent

import (
	"errors"
	"reflect"
	"testing"

	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

func TestParseKernelCommandLine(t *testing.T) {
	cmdline := "console=ttyS0 keel.cmd=WyIvYmluL3NoIiwiLWxjIiwiZWNobyBoaSJd keel.cwd=/workspace keel.features=W3sibmFtZSI6ImRvY2tlciIsImNvbmZpZyI6eyJzdG9yYWdlX2RyaXZlciI6InZmcyJ9fV0"

	cfg, err := parseKernelCommandLine(cmdline)
	if err != nil {
		t.Fatalf("parseKernelCommandLine() error = %v", err)
	}
	if got, want := cfg.WorkDir, "/workspace"; got != want {
		t.Fatalf("WorkDir = %q, want %q", got, want)
	}
	wantCommand := []string{"/bin/sh", "-lc", "echo hi"}
	if !reflect.DeepEqual(cfg.Command, wantCommand) {
		t.Fatalf("Command = %#v, want %#v", cfg.Command, wantCommand)
	}
	if len(cfg.Features) != 1 || cfg.Features[0].Name != "docker" {
		t.Fatalf("Features = %#v", cfg.Features)
	}
}

func TestRunInitDefaultsToShellAndPowersOff(t *testing.T) {
	var gotCommand []string
	var gotDir string
	var poweredOff bool

	err := runInit(bootConfig{WorkDir: "/workspace"}, initOps{
		chdir: func(dir string) error {
			gotDir = dir
			return nil
		},
		runCommand: func(cfg bootConfig, _ []string) error {
			gotCommand = append([]string(nil), cfg.Command...)
			return nil
		},
		powerOff: func() error {
			poweredOff = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runInit() error = %v", err)
	}
	if gotDir != "/workspace" {
		t.Fatalf("chdir dir = %q, want %q", gotDir, "/workspace")
	}
	wantCommand := []string{"/bin/sh"}
	if !reflect.DeepEqual(gotCommand, wantCommand) {
		t.Fatalf("command = %#v, want %#v", gotCommand, wantCommand)
	}
	if !poweredOff {
		t.Fatal("powerOff was not called")
	}
}

func TestRunInitReturnsCommandErrorWithoutPowerOff(t *testing.T) {
	commandErr := errors.New("boom")
	var poweredOff bool

	err := runInit(bootConfig{Command: []string{"/bin/false"}}, initOps{
		chdir: func(string) error { return nil },
		runCommand: func(_ bootConfig, _ []string) error {
			return commandErr
		},
		powerOff: func() error {
			poweredOff = true
			return nil
		},
	})
	if !errors.Is(err, commandErr) {
		t.Fatalf("runInit() error = %v, want %v", err, commandErr)
	}
	if poweredOff {
		t.Fatal("powerOff was called after command error")
	}
}

func TestBootMountsCoreFilesystemsBeforeLoadingConfig(t *testing.T) {
	var calls []string

	err := boot(bootOps{
		loadBootConfig: func() (bootConfig, error) {
			calls = append(calls, "load-config")
			return bootConfig{WorkDir: "/workspace"}, nil
		},
		mountCoreFilesystems: func() error {
			calls = append(calls, "mount-core")
			return nil
		},
		mountWorkspace: func(string) error {
			calls = append(calls, "mount-workspace")
			return nil
		},
		mountVolumes: func([]volumeMount, *processConfig) error {
			calls = append(calls, "mount-volumes")
			return nil
		},
		attachConsole: func() error {
			calls = append(calls, "attach-console")
			return nil
		},
		runInit: func(bootConfig, initOps) error {
			calls = append(calls, "run-init")
			return nil
		},
		initOps: initOps{},
	})
	if err != nil {
		t.Fatalf("boot() error = %v", err)
	}
	wantCalls := []string{"mount-core", "load-config", "mount-workspace", "mount-volumes", "attach-console", "run-init"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestCoreMountsIncludesCgroup2(t *testing.T) {
	mounts := coreMounts()
	for _, mount := range mounts {
		if mount.target == "/sys/fs/cgroup" && mount.fstype == "cgroup2" {
			return
		}
	}
	t.Fatalf("coreMounts() = %#v, want cgroup2 mount", mounts)
}

func TestParseKernelCommandLineParsesProcessConfig(t *testing.T) {
	cmdline := "console=ttyS0 keel.process=eyJ1aWQiOjEwMDAsImdpZCI6MTAwMSwic3VwcGxlbWVudGFyeV9naWRzIjpbMjcsNDRdfQ"

	cfg, err := parseKernelCommandLine(cmdline)
	if err != nil {
		t.Fatalf("parseKernelCommandLine() error = %v", err)
	}
	if cfg.Process == nil {
		t.Fatal("Process = nil, want non-nil")
	}
	want := &processConfig{
		UID:               1000,
		GID:               1001,
		SupplementaryGIDs: []int{27, 44},
	}
	if !reflect.DeepEqual(cfg.Process, want) {
		t.Fatalf("Process = %#v, want %#v", cfg.Process, want)
	}
}

func TestParseKernelCommandLineParsesMetadataDevice(t *testing.T) {
	cfg, err := parseKernelCommandLine("console=ttyS0 keel.meta=/dev/vdc")
	if err != nil {
		t.Fatalf("parseKernelCommandLine() error = %v", err)
	}
	if got, want := cfg.MetadataDevice, "/dev/vdc"; got != want {
		t.Fatalf("MetadataDevice = %q, want %q", got, want)
	}
}

func TestApplyBootManifestSetsCommandEnvProcessAndVolumes(t *testing.T) {
	cfg := bootConfig{}
	applyBootManifest(&cfg, pkgboot.Manifest{
		Command: []string{"/bin/sh", "-lc", "echo hi"},
		CWD:     "/workspace",
		Env: map[string]string{
			"TERM": "xterm-256color",
		},
		Process: &pkgboot.ProcessConfig{
			UID: 1000,
			GID: 1001,
		},
		Volumes: []pkgboot.VolumeMount{{
			Device:    "/dev/vdd",
			Target:    "/cache",
			Kind:      "dir",
			Ownership: "process",
		}},
	})
	if got, want := cfg.WorkDir, "/workspace"; got != want {
		t.Fatalf("WorkDir = %q, want %q", got, want)
	}
	if len(cfg.Command) != 3 || cfg.Command[2] != "echo hi" {
		t.Fatalf("Command = %#v", cfg.Command)
	}
	if got, want := cfg.Env["TERM"], "xterm-256color"; got != want {
		t.Fatalf("Env[TERM] = %q, want %q", got, want)
	}
	if cfg.Process == nil || cfg.Process.UID != 1000 || cfg.Process.GID != 1001 {
		t.Fatalf("Process = %#v", cfg.Process)
	}
	if len(cfg.Volumes) != 1 || cfg.Volumes[0].Device != "/dev/vdd" {
		t.Fatalf("Volumes = %#v", cfg.Volumes)
	}
}

func TestRunInitPassesProcessConfigToRunCommand(t *testing.T) {
	wantProcess := &processConfig{
		UID:               1000,
		GID:               1001,
		SupplementaryGIDs: []int{27},
	}
	var gotProcess *processConfig

	err := runInit(bootConfig{
		Command: []string{"/bin/true"},
		Process: wantProcess,
	}, initOps{
		chdir: func(string) error { return nil },
		runCommand: func(cfg bootConfig, _ []string) error {
			gotProcess = cfg.Process
			return nil
		},
		powerOff: func() error { return nil },
	})
	if err != nil {
		t.Fatalf("runInit() error = %v", err)
	}
	if !reflect.DeepEqual(gotProcess, wantProcess) {
		t.Fatalf("Process = %#v, want %#v", gotProcess, wantProcess)
	}
}

func TestRunInitPassesManifestEnvToRunCommand(t *testing.T) {
	var gotEnv []string
	err := runInit(bootConfig{
		Command: []string{"/bin/true"},
		Env: map[string]string{
			"TERM": "xterm-256color",
			"CI":   "1",
		},
	}, initOps{
		chdir: func(string) error { return nil },
		runCommand: func(_ bootConfig, env []string) error {
			gotEnv = append([]string(nil), env...)
			return nil
		},
		powerOff: func() error { return nil },
	})
	if err != nil {
		t.Fatalf("runInit() error = %v", err)
	}
	if !containsEnv(gotEnv, "TERM=xterm-256color") || !containsEnv(gotEnv, "CI=1") {
		t.Fatalf("env = %#v, want TERM and CI", gotEnv)
	}
}

func containsEnv(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
