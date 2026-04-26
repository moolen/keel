package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type LoadOptions struct {
	WorkingDir string
}

type OverrideConfig struct {
	Image   string
	Command []string
	Verbose bool
	DryRun  bool
}

type mergePresenceConfig struct {
	Network mergePresenceNetworkConfig `yaml:"network"`
}

type mergePresenceNetworkConfig struct {
	Audit *bool                    `yaml:"audit"`
	MITM  *mergePresenceMITMConfig `yaml:"mitm"`
	HTTP  *mergePresenceHTTPConfig `yaml:"http"`
}

type mergePresenceMITMConfig struct {
	Enabled         *bool                    `yaml:"enabled"`
	Mode            *string                  `yaml:"mode"`
	OnUntrustedCert *string                  `yaml:"on_untrusted_cert"`
	LogRequests     *bool                    `yaml:"log_requests"`
	CA              *mergePresenceMITMCA     `yaml:"ca"`
	Bypass          *mergePresenceMITMBypass `yaml:"bypass"`
}

type mergePresenceMITMCA struct {
	Name          *string `yaml:"name"`
	InstallSystem *bool   `yaml:"install_system"`
	InstallDocker *bool   `yaml:"install_docker"`
}

type mergePresenceMITMBypass struct {
	Hosts *[]string `yaml:"hosts"`
	SNI   *[]string `yaml:"sni"`
}

type mergePresenceHTTPConfig struct {
	Default *string           `yaml:"default"`
	Rules   *[]HTTPRuleConfig `yaml:"rules"`
}

func Load(opts LoadOptions) (Config, error) {
	cfg := Default()

	wd := opts.WorkingDir
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return Config{}, err
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, err
	}

	if err := mergeConfigFile(&cfg, filepath.Join(home, ".config", "keel", "config.yaml")); err != nil {
		return Config{}, err
	}

	projectConfig, err := findProjectConfig(wd)
	if err != nil {
		return Config{}, err
	}
	if projectConfig != "" {
		if err := mergeConfigFile(&cfg, projectConfig); err != nil {
			return Config{}, err
		}
	}

	cfg.ImageCacheDir = expandHome(cfg.ImageCacheDir)
	cfg.KernelPath = expandHome(cfg.KernelPath)
	cfg.Kernel.Path = expandHome(cfg.Kernel.Path)
	if cfg.Kernel.Path == "" {
		cfg.Kernel.Path = cfg.KernelPath
	}
	return cfg, nil
}

func ApplyOverrides(cfg Config, overrides OverrideConfig) Config {
	if overrides.Image != "" {
		cfg.Image = overrides.Image
	}
	if len(overrides.Command) > 0 {
		cfg.Command = append([]string(nil), overrides.Command...)
	}
	cfg.Verbose = overrides.Verbose
	cfg.DryRun = overrides.DryRun
	return cfg
}

func mergeConfigFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	var fileCfg Config
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return err
	}

	var presenceCfg mergePresenceConfig
	if err := yaml.Unmarshal(data, &presenceCfg); err != nil {
		return err
	}

	mergeConfig(cfg, fileCfg, presenceCfg)
	return nil
}

func mergeConfig(dst *Config, src Config, presence mergePresenceConfig) {
	if src.Image != "" {
		dst.Image = src.Image
	}
	if src.ImageCacheDir != "" {
		dst.ImageCacheDir = src.ImageCacheDir
	}
	if src.KernelPath != "" {
		dst.KernelPath = src.KernelPath
		dst.Kernel.Path = src.KernelPath
	}
	if src.Kernel.Path != "" {
		dst.Kernel.Path = src.Kernel.Path
	}
	if src.Resources.VCPU != 0 {
		dst.Resources.VCPU = src.Resources.VCPU
	}
	if src.Resources.MemoryMB != 0 {
		dst.Resources.MemoryMB = src.Resources.MemoryMB
	}
	if src.Resources.DiskMB != 0 {
		dst.Resources.DiskMB = src.Resources.DiskMB
	}
	if src.DefaultResources.VCPU != 0 {
		dst.DefaultResources.VCPU = src.DefaultResources.VCPU
		dst.Resources.VCPU = src.DefaultResources.VCPU
	}
	if src.DefaultResources.MemoryMB != 0 {
		dst.DefaultResources.MemoryMB = src.DefaultResources.MemoryMB
		dst.Resources.MemoryMB = src.DefaultResources.MemoryMB
	}
	if src.DefaultResources.DiskMB != 0 {
		dst.DefaultResources.DiskMB = src.DefaultResources.DiskMB
		dst.Resources.DiskMB = src.DefaultResources.DiskMB
	}
	if src.Workspace.Mount != "" {
		dst.Workspace.Mount = src.Workspace.Mount
	}
	if src.Workspace.Target != "" {
		dst.Workspace.Target = src.Workspace.Target
	}
	dst.Workspace.SyncBack = dst.Workspace.SyncBack || src.Workspace.SyncBack
	dst.Workspace.SyncDeletes = dst.Workspace.SyncDeletes || src.Workspace.SyncDeletes
	if src.Workspace.SyncConfirm {
		dst.Workspace.SyncConfirm = true
	}
	if src.Network.Mode != "" {
		dst.Network.Mode = src.Network.Mode
	}
	if presence.Network.Audit != nil {
		dst.Network.Audit = src.Network.Audit
	}
	dst.Network.DenyIfNoSNI = dst.Network.DenyIfNoSNI || src.Network.DenyIfNoSNI
	if len(src.Network.DNS.Allowed) > 0 {
		dst.Network.DNS.Allowed = append([]string(nil), src.Network.DNS.Allowed...)
	}
	if len(src.Network.DNS.Denied) > 0 {
		dst.Network.DNS.Denied = append([]string(nil), src.Network.DNS.Denied...)
	}
	if len(src.Network.TCP.AllowedCIDRs) > 0 {
		dst.Network.TCP.AllowedCIDRs = append([]string(nil), src.Network.TCP.AllowedCIDRs...)
	}
	if len(src.Network.TCP.DeniedCIDRs) > 0 {
		dst.Network.TCP.DeniedCIDRs = append([]string(nil), src.Network.TCP.DeniedCIDRs...)
	}
	if len(src.Network.TLS.AllowedSNI) > 0 {
		dst.Network.TLS.AllowedSNI = append([]string(nil), src.Network.TLS.AllowedSNI...)
	}
	if len(src.Network.TLS.DeniedSNI) > 0 {
		dst.Network.TLS.DeniedSNI = append([]string(nil), src.Network.TLS.DeniedSNI...)
	}
	if presence.Network.MITM != nil {
		if presence.Network.MITM.Mode != nil {
			dst.Network.MITM.Mode = src.Network.MITM.Mode
		}
		if presence.Network.MITM.Enabled != nil {
			dst.Network.MITM.Enabled = src.Network.MITM.Enabled
		}
		if presence.Network.MITM.OnUntrustedCert != nil {
			dst.Network.MITM.OnUntrustedCert = src.Network.MITM.OnUntrustedCert
		}
		if presence.Network.MITM.LogRequests != nil {
			dst.Network.MITM.LogRequests = src.Network.MITM.LogRequests
		}
		if presence.Network.MITM.CA != nil {
			if presence.Network.MITM.CA.Name != nil {
				dst.Network.MITM.CA.Name = src.Network.MITM.CA.Name
			}
			if presence.Network.MITM.CA.InstallSystem != nil {
				dst.Network.MITM.CA.InstallSystem = src.Network.MITM.CA.InstallSystem
			}
			if presence.Network.MITM.CA.InstallDocker != nil {
				dst.Network.MITM.CA.InstallDocker = src.Network.MITM.CA.InstallDocker
			}
		}
		if presence.Network.MITM.Bypass != nil {
			if presence.Network.MITM.Bypass.Hosts != nil {
				dst.Network.MITM.Bypass.Hosts = append([]string{}, src.Network.MITM.Bypass.Hosts...)
			}
			if presence.Network.MITM.Bypass.SNI != nil {
				dst.Network.MITM.Bypass.SNI = append([]string{}, src.Network.MITM.Bypass.SNI...)
			}
		}
	}
	if presence.Network.HTTP != nil {
		if presence.Network.HTTP.Default != nil {
			dst.Network.HTTP.Default = src.Network.HTTP.Default
		}
		if presence.Network.HTTP.Rules != nil {
			dst.Network.HTTP.Rules = append([]HTTPRuleConfig{}, src.Network.HTTP.Rules...)
		}
	}
	if len(src.Features) > 0 {
		dst.Features = append([]FeatureConfig(nil), src.Features...)
	}
	if len(src.Env) > 0 {
		if dst.Env == nil {
			dst.Env = map[string]string{}
		}
		for k, v := range src.Env {
			dst.Env[k] = v
		}
	}
}

func findProjectConfig(start string) (string, error) {
	current := start
	for {
		path := filepath.Join(current, "keel.yaml")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", nil
		}
		current = parent
	}
}

func expandHome(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}
