package features

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	dockerBridgeCIDR   = "172.17.0.1/16"
	dockerBridgeSubnet = "172.17.0.0/16"
	dockerProxyURL     = "http://172.17.0.1:3128"
	dockerCgroupParent = "/keel/docker"
	dockerLegacyBinDir = "/run/keel-docker-bin"
)

type ConfiguredFeature struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
}

type DockerConfig struct {
	StorageDriver   string   `json:"storage_driver"`
	RegistryMirrors []string `json:"registry_mirrors"`
	MITMCAPEM       string   `json:"mitm_ca_pem"`
}

type Runner struct {
	LookupPath       func(string) (string, error)
	Stat             func(string) (os.FileInfo, error)
	MkdirAll         func(string, os.FileMode) error
	WriteFile        func(string, []byte, os.FileMode) error
	Remove           func(string) error
	RemoveAll        func(string) error
	StartProcess     func(context.Context, string, []string, []string, string, int) error
	WaitForFile      func(string) error
	WaitForDaemon    func([]string) error
	RunCommand       func(string, ...string) error
	WorkloadCgroupFD int
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
	cfg, err := decodeDockerConfig(raw)
	if err != nil {
		return err
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
	iptablesPath, err := findBinary(lookupPath, stat, "iptables", []string{"/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables", "/bin/iptables"})
	if err != nil {
		return fmt.Errorf("docker feature requires iptables in PATH: %w", err)
	}
	if legacyPath, ok := findOptionalBinary(lookupPath, stat, "iptables-legacy", []string{"/usr/sbin/iptables-legacy", "/sbin/iptables-legacy", "/usr/bin/iptables-legacy", "/bin/iptables-legacy"}); ok {
		iptablesPath = legacyPath
	}
	ip6tablesLegacyPath, hasIP6TablesLegacy := findOptionalBinary(lookupPath, stat, "ip6tables-legacy", []string{"/usr/sbin/ip6tables-legacy", "/sbin/ip6tables-legacy", "/usr/bin/ip6tables-legacy", "/bin/ip6tables-legacy"})

	mkdirAll := r.MkdirAll
	if mkdirAll == nil {
		mkdirAll = os.MkdirAll
	}
	for _, dir := range []string{"/etc/docker", "/etc/docker/client", "/var/lib/docker", "/var/run"} {
		if err := mkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.MITMCAPEM) != "" {
		for _, dir := range []string{"/etc/docker/certs.d/keel-mitm", "/usr/local", "/usr/local/share", "/usr/local/share/ca-certificates"} {
			if err := mkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
	}

	daemonConfig := map[string]any{
		"storage-driver":   cfg.StorageDriver,
		"registry-mirrors": cfg.RegistryMirrors,
		"iptables":         true,
		"ip6tables":        false,
		"bip":              dockerBridgeCIDR,
		"dns":              []string{"172.17.0.1"},
		"ip-forward":       true,
		"ip-masq":          true,
		"userland-proxy":   false,
	}
	if r.WorkloadCgroupFD > 0 {
		daemonConfig["cgroup-parent"] = dockerCgroupParent
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
	clientConfig, err := json.Marshal(map[string]any{
		"proxies": map[string]any{
			"default": map[string]string{
				"httpProxy":  dockerProxyURL,
				"httpsProxy": dockerProxyURL,
				"noProxy":    "127.0.0.1,localhost,::1,172.17.0.1",
			},
		},
	})
	if err != nil {
		return err
	}
	if err := writeFile("/etc/docker/client/config.json", clientConfig, 0o644); err != nil {
		return err
	}
	runCommand := r.RunCommand
	if runCommand == nil {
		runCommand = runGuestCommand
	}
	daemonEnv := env
	if strings.HasSuffix(iptablesPath, "iptables-legacy") {
		if err := installDockerCommandWrapper(mkdirAll, writeFile, "iptables", iptablesPath); err != nil {
			return err
		}
		if hasIP6TablesLegacy {
			if err := installDockerCommandWrapper(mkdirAll, writeFile, "ip6tables", ip6tablesLegacyPath); err != nil {
				return err
			}
		}
		daemonEnv = prependEnvPath(env, dockerLegacyBinDir)
	}
	daemonEnv = appendEnvIfMissing(daemonEnv, "DOCKER_INSECURE_NO_IPTABLES_RAW=1")
	if strings.TrimSpace(cfg.MITMCAPEM) != "" {
		if err := writeFile("/etc/docker/certs.d/keel-mitm/ca.crt", []byte(cfg.MITMCAPEM), 0o644); err != nil {
			return err
		}
		if err := writeFile("/usr/local/share/ca-certificates/keel-local-ca.crt", []byte(cfg.MITMCAPEM), 0o644); err != nil {
			return err
		}
		if err := activateDockerMITMTrust(lookupPath, stat, runCommand); err != nil {
			return err
		}
	}
	remove := r.Remove
	if remove == nil {
		remove = os.Remove
	}
	removeAll := r.RemoveAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	if err := ensureDockerForwarding(writeFile, stat); err != nil {
		return err
	}
	if err := removeAll("/var/run/docker"); err != nil {
		return err
	}
	if err := mkdirAll("/var/run/docker", 0o755); err != nil {
		return err
	}
	if err := remove("/var/run/docker.sock"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := remove("/var/run/docker.pid"); err != nil && !os.IsNotExist(err) {
		return err
	}

	startProcess := r.StartProcess
	if startProcess == nil {
		startProcess = startGuestProcess
	}
	if err := startProcess(ctx, dockerdPath, []string{"--host=unix:///var/run/docker.sock", "--config-file=/etc/docker/daemon.json"}, daemonEnv, "/", r.WorkloadCgroupFD); err != nil {
		return err
	}

	waitForFile := r.WaitForFile
	if waitForFile == nil {
		waitForFile = waitForSocket
	}
	if err := waitForFile("/var/run/docker.sock"); err != nil {
		return err
	}
	waitForDaemon := r.WaitForDaemon
	if waitForDaemon == nil {
		waitForDaemon = waitForDockerDaemon
	}
	if err := waitForDaemon(daemonEnv); err != nil {
		return err
	}
	return ensureDockerTransparentRedirect(runCommand, iptablesPath)
}

func activateDockerMITMTrust(lookupPath func(string) (string, error), stat func(string) (os.FileInfo, error), runCommand func(string, ...string) error) error {
	path, ok := findOptionalBinary(lookupPath, stat, "update-ca-certificates", []string{"/usr/sbin/update-ca-certificates", "/usr/bin/update-ca-certificates", "/sbin/update-ca-certificates", "/bin/update-ca-certificates"})
	if !ok {
		// Docker also reads /etc/docker/certs.d; images without a system trust updater still get Docker-specific trust.
		return nil
	}
	if err := runCommand(path); err != nil {
		return fmt.Errorf("activate docker MITM CA trust: %w", err)
	}
	return nil
}

func decodeDockerConfig(raw map[string]any) (DockerConfig, error) {
	cfg := DockerConfig{StorageDriver: "vfs"}
	if len(raw) == 0 {
		return cfg, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return DockerConfig{}, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DockerConfig{}, err
	}
	if cfg.StorageDriver == "" {
		cfg.StorageDriver = "vfs"
	}
	return cfg, nil
}

func installDockerCommandWrapper(mkdirAll func(string, os.FileMode) error, writeFile func(string, []byte, os.FileMode) error, name, target string) error {
	if err := mkdirAll(dockerLegacyBinDir, 0o755); err != nil {
		return err
	}
	body := []byte("#!/bin/sh\nexec " + target + " \"$@\"\n")
	if err := writeFile(dockerLegacyBinDir+"/"+name, body, 0o755); err != nil {
		return fmt.Errorf("write docker %s wrapper: %w", name, err)
	}
	return nil
}

func prependEnvPath(env []string, dir string) []string {
	out := append([]string(nil), env...)
	for i, entry := range out {
		if strings.HasPrefix(entry, "PATH=") {
			out[i] = "PATH=" + dir + ":" + strings.TrimPrefix(entry, "PATH=")
			return out
		}
	}
	return append(out, "PATH="+dir)
}

func appendEnvIfMissing(env []string, entry string) []string {
	key, _, ok := strings.Cut(entry, "=")
	if !ok {
		return append(env, entry)
	}
	prefix := key + "="
	for _, existing := range env {
		if strings.HasPrefix(existing, prefix) {
			return env
		}
	}
	return append(env, entry)
}

func startGuestProcess(ctx context.Context, name string, args []string, env []string, dir string, cgroupFD int) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cgroupFD > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			UseCgroupFD: true,
			CgroupFD:    cgroupFD,
		}
	}
	return cmd.Start()
}

func runGuestCommand(name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func ensureDockerTransparentRedirect(runCommand func(string, ...string) error, iptablesPath string) error {
	if runCommand == nil {
		return nil
	}
	redirectRule := []string{"-t", "nat", "-A", "PREROUTING", "-s", dockerBridgeSubnet, "-p", "tcp", "-j", "REDIRECT", "--to-ports", "3128"}
	skipProxyRule := []string{"-t", "nat", "-I", "PREROUTING", "1", "-s", dockerBridgeSubnet, "-p", "tcp", "-d", "172.17.0.1", "--dport", "3128", "-j", "RETURN"}
	if err := runCommand(iptablesPath, skipProxyRule...); err != nil {
		return fmt.Errorf("configure docker proxy bypass: %w", err)
	}
	if err := runCommand(iptablesPath, redirectRule...); err != nil {
		return fmt.Errorf("configure docker transparent redirect: %w", err)
	}
	return nil
}

func ensureDockerForwarding(writeFile func(string, []byte, os.FileMode) error, stat func(string) (os.FileInfo, error)) error {
	if writeFile == nil {
		return nil
	}
	for _, setting := range []struct {
		path  string
		value string
	}{
		{path: "/proc/sys/net/ipv4/ip_forward", value: "1\n"},
		{path: "/proc/sys/net/ipv4/conf/all/forwarding", value: "1\n"},
	} {
		if err := writeFile(setting.path, []byte(setting.value), 0o644); err != nil {
			return fmt.Errorf("enable docker forwarding at %s: %w", setting.path, err)
		}
	}
	if stat == nil {
		stat = os.Stat
	}
	const bridgeNetfilterPath = "/proc/sys/net/bridge/bridge-nf-call-iptables"
	if _, err := stat(bridgeNetfilterPath); err == nil {
		if err := writeFile(bridgeNetfilterPath, []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("enable docker bridge netfilter at %s: %w", bridgeNetfilterPath, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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

func waitForDockerDaemon(env []string) error {
	_ = env
	for range 50 {
		if err := dockerDaemonReady("/var/run/docker.sock"); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("docker daemon did not become ready")
}

func dockerDaemonReady(socketPath string) error {
	conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()
	if err := conn.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("GET /_ping HTTP/1.0\r\nHost: docker\r\n\r\n")); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(status, "200") {
		return fmt.Errorf("unexpected docker ping status: %s", strings.TrimSpace(status))
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if !strings.Contains(string(body), "OK") {
		return fmt.Errorf("unexpected docker ping body: %q", string(body))
	}
	return nil
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

func findOptionalBinary(lookupPath func(string) (string, error), stat func(string) (os.FileInfo, error), name string, candidates []string) (string, bool) {
	path, err := findBinary(lookupPath, stat, name, candidates)
	return path, err == nil
}
