package agent

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseKernelCommandLine(t *testing.T) {
	cmdline := "console=ttyS0 keel.cmd=WyIvYmluL3NoIiwiLWxjIiwiZWNobyBoaSJd keel.cwd=/workspace"

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
		runCommand: func(command []string, _ []string) error {
			gotCommand = append([]string(nil), command...)
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
		runCommand: func(_ []string, _ []string) error {
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
	wantCalls := []string{"mount-core", "load-config", "mount-workspace", "attach-console", "run-init"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}
