package features

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestRunConfiguredStartsDockerDaemon(t *testing.T) {
	tempDir := t.TempDir()
	var wrotePath string
	var wroteBody []byte
	var startedName string
	var startedArgs []string
	var startedEnv []string

	runner := Runner{
		LookupPath: func(file string) (string, error) {
			return "/usr/local/bin/" + file, nil
		},
		MkdirAll: func(path string, _ os.FileMode) error {
			return nil
		},
		WriteFile: func(path string, data []byte, _ os.FileMode) error {
			wrotePath = path
			wroteBody = append([]byte(nil), data...)
			return nil
		},
		StartProcess: func(_ context.Context, name string, args []string, env []string, dir string) error {
			startedName = name
			startedArgs = append([]string(nil), args...)
			startedEnv = append([]string(nil), env...)
			if dir != "/" {
				t.Fatalf("start dir = %q, want /", dir)
			}
			return nil
		},
		WaitForFile: func(path string) error {
			if path != "/var/run/docker.sock" {
				t.Fatalf("WaitForFile path = %q, want /var/run/docker.sock", path)
			}
			return nil
		},
	}

	err := runner.RunConfigured(context.Background(), []ConfiguredFeature{{
		Name: "docker",
		Config: map[string]any{
			"storage_driver":   "vfs",
			"registry_mirrors": []any{"https://mirror.gcr.io"},
		},
	}}, []string{"HTTPS_PROXY=http://127.0.0.1:3128", "PATH=" + tempDir})
	if err != nil {
		t.Fatalf("RunConfigured() error = %v", err)
	}

	if wrotePath != "/etc/docker/daemon.json" {
		t.Fatalf("WriteFile path = %q, want /etc/docker/daemon.json", wrotePath)
	}
	text := string(wroteBody)
	for _, want := range []string{`"storage-driver":"vfs"`, `"https://mirror.gcr.io"`, `"iptables":false`, `"bridge":"none"`, `"userland-proxy":false`} {
		if !strings.Contains(text, want) {
			t.Fatalf("daemon.json missing %q in %s", want, text)
		}
	}
	if startedName != "/usr/local/bin/dockerd" {
		t.Fatalf("StartProcess name = %q, want /usr/local/bin/dockerd", startedName)
	}
	if !reflect.DeepEqual(startedArgs, []string{"--host=unix:///var/run/docker.sock", "--config-file=/etc/docker/daemon.json"}) {
		t.Fatalf("StartProcess args = %#v", startedArgs)
	}
	if !containsEnv(startedEnv, "HTTPS_PROXY=http://127.0.0.1:3128") {
		t.Fatalf("StartProcess env missing proxy: %#v", startedEnv)
	}
}

func TestRunConfiguredSkipsWhenDockerFeatureAbsent(t *testing.T) {
	runner := Runner{}
	if err := runner.RunConfigured(context.Background(), nil, nil); err != nil {
		t.Fatalf("RunConfigured() error = %v", err)
	}
}

func TestRunConfiguredRejectsMissingDockerd(t *testing.T) {
	runner := Runner{
		LookupPath: func(file string) (string, error) {
			return "", os.ErrNotExist
		},
		Stat: func(string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}
	err := runner.RunConfigured(context.Background(), []ConfiguredFeature{{Name: "docker"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "docker feature requires") {
		t.Fatalf("RunConfigured() error = %v", err)
	}
}

func containsEnv(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}
