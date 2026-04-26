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
	writes := map[string]string{}
	var startedName string
	var startedArgs []string
	var startedEnv []string
	var waitedForDaemon bool
	var daemonEnv []string
	var removedPaths []string
	var removedAllPaths []string

	runner := Runner{
		LookupPath: func(file string) (string, error) {
			return "/usr/local/bin/" + file, nil
		},
		MkdirAll: func(path string, _ os.FileMode) error {
			return nil
		},
		WriteFile: func(path string, data []byte, _ os.FileMode) error {
			writes[path] = string(append([]byte(nil), data...))
			return nil
		},
		Remove: func(path string) error {
			removedPaths = append(removedPaths, path)
			return nil
		},
		RemoveAll: func(path string) error {
			removedAllPaths = append(removedAllPaths, path)
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
		WaitForDaemon: func(env []string) error {
			waitedForDaemon = true
			daemonEnv = append([]string(nil), env...)
			return nil
		},
	}

	err := runner.RunConfigured(context.Background(), []ConfiguredFeature{{
		Name: "docker",
		Config: map[string]any{
			"storage_driver":   "vfs",
			"registry_mirrors": []any{"https://mirror.gcr.io"},
		},
	}}, []string{"HTTPS_PROXY=http://127.0.0.1:3128", "DOCKER_CONFIG=/etc/docker/client", "PATH=" + tempDir})
	if err != nil {
		t.Fatalf("RunConfigured() error = %v", err)
	}

	if _, ok := writes["/etc/docker/daemon.json"]; !ok {
		t.Fatalf("daemon config was not written: %#v", writes)
	}
	text := writes["/etc/docker/daemon.json"]
	for _, want := range []string{`"storage-driver":"vfs"`, `"https://mirror.gcr.io"`, `"iptables":false`, `"ip-forward":false`, `"ip-masq":false`, `"bip":"172.17.0.1/16"`, `"userland-proxy":false`} {
		if !strings.Contains(text, want) {
			t.Fatalf("daemon.json missing %q in %s", want, text)
		}
	}
	if strings.Contains(text, `"bridge":"`) {
		t.Fatalf("daemon.json should not set explicit bridge device: %s", text)
	}
	clientConfig := writes["/etc/docker/client/config.json"]
	for _, want := range []string{`"httpProxy":"http://172.17.0.1:3128"`, `"httpsProxy":"http://172.17.0.1:3128"`, `"noProxy":"127.0.0.1,localhost,::1,172.17.0.1"`} {
		if !strings.Contains(clientConfig, want) {
			t.Fatalf("client config missing %q in %s", want, clientConfig)
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
	if !containsEnv(startedEnv, "DOCKER_CONFIG=/etc/docker/client") {
		t.Fatalf("StartProcess env missing DOCKER_CONFIG: %#v", startedEnv)
	}
	if !containsEnv(daemonEnv, "DOCKER_CONFIG=/etc/docker/client") {
		t.Fatalf("WaitForDaemon env missing DOCKER_CONFIG: %#v", daemonEnv)
	}
	if !containsEnv(daemonEnv, "PATH="+tempDir) {
		t.Fatalf("WaitForDaemon env missing PATH override: %#v", daemonEnv)
	}
	if !reflect.DeepEqual(removedPaths, []string{"/var/run/docker.sock", "/var/run/docker.pid"}) {
		t.Fatalf("Remove paths = %#v, want docker socket and pid cleanup", removedPaths)
	}
	if !reflect.DeepEqual(removedAllPaths, []string{"/var/run/docker"}) {
		t.Fatalf("RemoveAll paths = %#v, want docker runtime dir cleanup", removedAllPaths)
	}
	if !waitedForDaemon {
		t.Fatal("expected WaitForDaemon to be called")
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

func TestDockerFeatureWritesCACertWhenConfigured(t *testing.T) {
	writes := map[string]string{}
	runner := Runner{
		LookupPath: func(file string) (string, error) {
			return "/usr/local/bin/" + file, nil
		},
		MkdirAll: func(path string, _ os.FileMode) error {
			return nil
		},
		WriteFile: func(path string, data []byte, _ os.FileMode) error {
			writes[path] = string(append([]byte(nil), data...))
			return nil
		},
		Remove:        func(string) error { return nil },
		RemoveAll:     func(string) error { return nil },
		StartProcess:  func(context.Context, string, []string, []string, string) error { return nil },
		WaitForFile:   func(string) error { return nil },
		WaitForDaemon: func([]string) error { return nil },
	}

	err := runner.RunConfigured(context.Background(), []ConfiguredFeature{{
		Name: "docker",
		Config: map[string]any{
			"mitm_ca_pem": "-----BEGIN CERTIFICATE-----\ntrust\n-----END CERTIFICATE-----\n",
		},
	}}, []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatalf("RunConfigured() error = %v", err)
	}
	if got := writes["/etc/docker/certs.d/keel-mitm/ca.crt"]; !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Fatalf("docker trust cert = %q", got)
	}
	if got := writes["/usr/local/share/ca-certificates/keel-local-ca.crt"]; !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Fatalf("system trust cert = %q", got)
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
