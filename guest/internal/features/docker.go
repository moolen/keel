package features

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type ConfiguredFeature struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
}

type DockerConfig struct {
	StorageDriver   string   `json:"storage_driver"`
	RegistryMirrors []string `json:"registry_mirrors"`
}

type Runner struct {
	LookupPath   func(string) (string, error)
	Stat         func(string) (os.FileInfo, error)
	MkdirAll     func(string, os.FileMode) error
	WriteFile    func(string, []byte, os.FileMode) error
	StartProcess func(context.Context, string, []string, []string, string) error
	WaitForFile  func(string) error
}

func (r Runner) RunConfigured(ctx context.Context, configured []ConfiguredFeature, env []string) error {
	for _, feature := range configured {
		if feature.Name != "docker" {
			continue
		}
		return r.startDocker(ctx, feature.Config, env)
	}
	return nil
}

func (r Runner) startDocker(ctx context.Context, raw map[string]any, env []string) error {
	cfg := DockerConfig{StorageDriver: "vfs"}
	if len(raw) > 0 {
		data, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
	}

	lookupPath := r.LookupPath
	if lookupPath == nil {
		lookupPath = exec.LookPath
	}
	stat := r.Stat
	if stat == nil {
		stat = os.Stat
	}
	dockerdPath, err := findBinary(lookupPath, stat, "dockerd", []string{"/usr/local/bin/dockerd", "/usr/bin/dockerd"})
	if err != nil {
		return fmt.Errorf("docker feature requires dockerd in PATH: %w", err)
	}
	if _, err := findBinary(lookupPath, stat, "docker", []string{"/usr/local/bin/docker", "/usr/bin/docker"}); err != nil {
		return fmt.Errorf("docker feature requires docker in PATH: %w", err)
	}

	mkdirAll := r.MkdirAll
	if mkdirAll == nil {
		mkdirAll = os.MkdirAll
	}
	for _, dir := range []string{"/etc/docker", "/var/lib/docker", "/var/run"} {
		if err := mkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	daemonConfig := map[string]any{
		"storage-driver":   cfg.StorageDriver,
		"registry-mirrors": cfg.RegistryMirrors,
		"iptables":         false,
		"bridge":           "none",
		"ip-forward":       false,
		"ip-masq":          false,
		"userland-proxy":   false,
	}
	body, err := json.Marshal(daemonConfig)
	if err != nil {
		return err
	}

	writeFile := r.WriteFile
	if writeFile == nil {
		writeFile = os.WriteFile
	}
	if err := writeFile("/etc/docker/daemon.json", body, 0o644); err != nil {
		return err
	}

	startProcess := r.StartProcess
	if startProcess == nil {
		startProcess = startGuestProcess
	}
	if err := startProcess(ctx, dockerdPath, []string{"--host=unix:///var/run/docker.sock", "--config-file=/etc/docker/daemon.json"}, env, "/"); err != nil {
		return err
	}

	waitForFile := r.WaitForFile
	if waitForFile == nil {
		waitForFile = waitForSocket
	}
	return waitForFile("/var/run/docker.sock")
}

func startGuestProcess(ctx context.Context, name string, args []string, env []string, dir string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func waitForSocket(path string) error {
	for range 100 {
		info, err := os.Stat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("docker socket %s did not appear", path)
}

func findBinary(lookupPath func(string) (string, error), stat func(string) (os.FileInfo, error), name string, candidates []string) (string, error) {
	path, err := lookupPath(name)
	if err == nil {
		return path, nil
	}
	for _, candidate := range candidates {
		if info, statErr := stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", err
}
