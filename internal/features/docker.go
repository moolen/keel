package features

import (
	"encoding/json"
	"errors"
)

type DockerFeature struct{}

type DockerConfig struct {
	StorageDriver   string   `json:"storage_driver"`
	RegistryMirrors []string `json:"registry_mirrors"`
}

func NewDockerFeature() DockerFeature {
	return DockerFeature{}
}

func (DockerFeature) Name() string {
	return "docker"
}

func (DockerFeature) ValidateConfig(raw map[string]any) error {
	var cfg DockerConfig
	if len(raw) > 0 {
		data, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
	}
	if cfg.StorageDriver == "" {
		return errors.New("storage_driver is required")
	}
	return nil
}
