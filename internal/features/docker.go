package features

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type DockerFeature struct{}

type DockerConfig struct {
	StorageDriver   string   `json:"storage_driver"`
	RegistryMirrors []string `json:"registry_mirrors"`
	MITMCAPEM       string   `json:"mitm_ca_pem"`
}

func NewDockerFeature() DockerFeature {
	return DockerFeature{}
}

func (DockerFeature) Name() string {
	return "docker"
}

func (DockerFeature) ValidateConfig(raw map[string]any) error {
	_, err := decodeDockerConfig(raw)
	return err
}

func (feature DockerFeature) NormalizeConfig(raw map[string]any) (NormalizedFeature, error) {
	cfg, err := decodeDockerConfig(raw)
	if err != nil {
		return NormalizedFeature{}, err
	}
	if cfg.StorageDriver == "" {
		cfg.StorageDriver = "vfs"
	}
	config := map[string]any{
		"storage_driver":   cfg.StorageDriver,
		"registry_mirrors": cfg.RegistryMirrors,
	}
	if strings.TrimSpace(cfg.MITMCAPEM) != "" {
		config["mitm_ca_pem"] = cfg.MITMCAPEM
	}
	return NormalizedFeature{Name: feature.Name(), Config: config}, nil
}

func decodeDockerConfig(raw map[string]any) (DockerConfig, error) {
	var cfg DockerConfig
	if len(raw) > 0 {
		data, err := json.Marshal(raw)
		if err != nil {
			return DockerConfig{}, err
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return DockerConfig{}, err
		}
	}
	return cfg, nil
}

func (DockerFeature) PrepareRootfs(rootfsPath string, _ map[string]any) error {
	if rootfsPath == "" {
		return fmt.Errorf("rootfs path is required")
	}
	missing := make([]string, 0, 2)
	for _, candidate := range []string{"/usr/local/bin/docker", "/usr/bin/docker"} {
		if rootfsContainsPath(rootfsPath, candidate) {
			goto foundDocker
		}
	}
	missing = append(missing, "docker")
foundDocker:
	for _, candidate := range []string{"/usr/local/bin/dockerd", "/usr/bin/dockerd"} {
		if rootfsContainsPath(rootfsPath, candidate) {
			goto foundDockerd
		}
	}
	missing = append(missing, "dockerd")
foundDockerd:
	if len(missing) > 0 {
		return fmt.Errorf("docker feature requires %s in the image rootfs; use a Docker-enabled base image", strings.Join(missing, " and "))
	}
	return nil
}

func rootfsContainsPath(rootfsPath, target string) bool {
	cmd := exec.CommandContext(context.Background(), "debugfs", "-R", "stat "+target, rootfsPath)
	output, err := cmd.CombinedOutput()
	return err == nil && !strings.Contains(string(output), "File not found")
}
