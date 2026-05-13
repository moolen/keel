package features

import (
	"context"
	"errors"
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
	var ranCommands [][]string

	runner := Runner{
		LookupPath: func(file string) (string, error) {
			if file == "iptables-legacy" || file == "ip6tables-legacy" {
				return "/usr/sbin/" + file, nil
			}
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
		StartProcess: func(_ context.Context, name string, args []string, env []string, dir string, cgroupFD int) error {
			startedName = name
			startedArgs = append([]string(nil), args...)
			startedEnv = append([]string(nil), env...)
			if dir != "/" {
				t.Fatalf("start dir = %q, want /", dir)
			}
			if cgroupFD != 11 {
				t.Fatalf("start cgroup fd = %d, want 11", cgroupFD)
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
		RunCommand: func(name string, args ...string) error {
			ranCommands = append(ranCommands, append([]string{name}, args...))
			return nil
		},
		WorkloadCgroupFD: 11,
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
	for _, want := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv4/conf/all/forwarding"} {
		if got := writes[want]; got != "1\n" {
			t.Fatalf("proc write %q = %q, want 1\\n", want, got)
		}
	}
	text := writes["/etc/docker/daemon.json"]
	for _, want := range []string{`"storage-driver":"vfs"`, `"https://mirror.gcr.io"`, `"iptables":true`, `"ip6tables":false`, `"dns":["172.17.0.1"]`, `"ip-forward":true`, `"ip-masq":true`, `"bip":"172.17.0.1/16"`, `"userland-proxy":false`, `"cgroup-parent":"/keel/docker"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("daemon.json missing %q in %s", want, text)
		}
	}
	if got := writes["/run/keel-docker-bin/iptables"]; !strings.Contains(got, "exec /usr/sbin/iptables-legacy") {
		t.Fatalf("iptables wrapper = %q, want legacy iptables exec", got)
	}
	if got := writes["/run/keel-docker-bin/ip6tables"]; !strings.Contains(got, "exec /usr/sbin/ip6tables-legacy") {
		t.Fatalf("ip6tables wrapper = %q, want legacy ip6tables exec", got)
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
	if !containsEnv(startedEnv, "DOCKER_INSECURE_NO_IPTABLES_RAW=1") {
		t.Fatalf("StartProcess env missing raw-table compatibility flag: %#v", startedEnv)
	}
	if !containsEnvPrefix(startedEnv, "PATH=/run/keel-docker-bin:"+tempDir) {
		t.Fatalf("StartProcess env missing legacy iptables PATH prefix: %#v", startedEnv)
	}
	if !containsEnv(daemonEnv, "DOCKER_CONFIG=/etc/docker/client") {
		t.Fatalf("WaitForDaemon env missing DOCKER_CONFIG: %#v", daemonEnv)
	}
	if !containsEnv(daemonEnv, "DOCKER_INSECURE_NO_IPTABLES_RAW=1") {
		t.Fatalf("WaitForDaemon env missing raw-table compatibility flag: %#v", daemonEnv)
	}
	if !containsEnvPrefix(daemonEnv, "PATH=/run/keel-docker-bin:"+tempDir) {
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
	if !reflect.DeepEqual(ranCommands, [][]string{
		{"/usr/sbin/iptables-legacy", "-t", "nat", "-I", "PREROUTING", "1", "-s", "172.17.0.0/16", "-p", "tcp", "-d", "172.17.0.1", "--dport", "3128", "-j", "RETURN"},
		{"/usr/sbin/iptables-legacy", "-t", "nat", "-A", "PREROUTING", "-s", "172.17.0.0/16", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "3128"},
	}) {
		t.Fatalf("RunCommand calls = %#v", ranCommands)
	}
}

func TestRunConfiguredSkipsWhenDockerFeatureAbsent(t *testing.T) {
	runner := Runner{}
	if err := runner.RunConfigured(context.Background(), nil, nil); err != nil {
		t.Fatalf("RunConfigured() error = %v", err)
	}
}

func TestDockerFeatureDefaultsStorageDriver(t *testing.T) {
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
		StartProcess:  func(context.Context, string, []string, []string, string, int) error { return nil },
		WaitForFile:   func(string) error { return nil },
		WaitForDaemon: func([]string) error { return nil },
		RunCommand:    func(string, ...string) error { return nil },
	}

	err := runner.RunConfigured(context.Background(), []ConfiguredFeature{{
		Name:   "docker",
		Config: map[string]any{},
	}}, []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatalf("RunConfigured() error = %v", err)
	}
	if got := writes["/etc/docker/daemon.json"]; !strings.Contains(got, `"storage-driver":"vfs"`) {
		t.Fatalf("daemon.json = %s, want storage-driver vfs", got)
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
	var events []string
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
		Remove:    func(string) error { return nil },
		RemoveAll: func(string) error { return nil },
		StartProcess: func(context.Context, string, []string, []string, string, int) error {
			events = append(events, "start-dockerd")
			return nil
		},
		WaitForFile:   func(string) error { return nil },
		WaitForDaemon: func([]string) error { return nil },
		RunCommand: func(name string, args ...string) error {
			events = append(events, name)
			return nil
		},
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
	if !reflect.DeepEqual(events[:2], []string{"/usr/local/bin/update-ca-certificates", "start-dockerd"}) {
		t.Fatalf("events = %#v, want trust update before dockerd start", events)
	}
}

func TestDockerFeatureRejectsFailedTrustActivation(t *testing.T) {
	var started bool
	runner := Runner{
		LookupPath: func(file string) (string, error) {
			return "/usr/local/bin/" + file, nil
		},
		MkdirAll:  func(string, os.FileMode) error { return nil },
		WriteFile: func(string, []byte, os.FileMode) error { return nil },
		Remove:    func(string) error { return nil },
		RemoveAll: func(string) error { return nil },
		StartProcess: func(context.Context, string, []string, []string, string, int) error {
			started = true
			return nil
		},
		WaitForFile:   func(string) error { return nil },
		WaitForDaemon: func([]string) error { return nil },
		RunCommand: func(name string, args ...string) error {
			if name == "/usr/local/bin/update-ca-certificates" {
				return errors.New("trust update failed")
			}
			return nil
		},
	}

	err := runner.RunConfigured(context.Background(), []ConfiguredFeature{{
		Name: "docker",
		Config: map[string]any{
			"mitm_ca_pem": "-----BEGIN CERTIFICATE-----\ntrust\n-----END CERTIFICATE-----\n",
		},
	}}, []string{"PATH=/usr/bin"})
	if err == nil || !strings.Contains(err.Error(), "activate docker MITM CA trust") {
		t.Fatalf("RunConfigured() error = %v, want trust activation failure", err)
	}
	if started {
		t.Fatal("dockerd started after failed trust activation")
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

func containsEnvPrefix(env []string, want string) bool {
	for _, entry := range env {
		if strings.HasPrefix(entry, want) {
			return true
		}
	}
	return false
}
