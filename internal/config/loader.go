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
	Network mergePresenceNetworkConfig  `yaml:"network"`
	Process *mergePresenceProcessConfig `yaml:"process"`
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

type mergePresenceProcessConfig struct {
	UID               *int   `yaml:"uid"`
	GID               *int   `yaml:"gid"`
	SupplementaryGIDs *[]int `yaml:"supplementary_gids"`
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
	cfg.Workspace.Mount = resolveHostPath(wd, cfg.Workspace.Mount)
	for i := range cfg.Volumes {
		cfg.Volumes[i].Source = resolveHostPath(wd, cfg.Volumes[i].Source)
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
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
	if src.Env.HasValues() {
		if dst.Env.Static == nil {
			dst.Env.Static = map[string]string{}
		}
		for k, v := range src.Env.Static {
			dst.Env.Static[k] = v
		}
		if dst.Env.FromHost == nil {
			dst.Env.FromHost = map[string]string{}
		}
		for k, v := range src.Env.FromHost {
			dst.Env.FromHost[k] = v
		}
		if dst.Env.FromCommand == nil {
			dst.Env.FromCommand = map[string]EnvCommand{}
		}
		for k, v := range src.Env.FromCommand {
			dst.Env.FromCommand[k] = v
		}
	}
	if len(src.Volumes) > 0 {
		dst.Volumes = append([]VolumeConfig(nil), src.Volumes...)
	}
	if presence.Process != nil {
		if dst.Process == nil {
			dst.Process = &ProcessConfig{}
		}
		if presence.Process.UID != nil {
			dst.Process.UID = src.Process.UID
			dst.Process.hasUID = true
		}
		if presence.Process.GID != nil {
			dst.Process.GID = src.Process.GID
			dst.Process.hasGID = true
		}
		if presence.Process.SupplementaryGIDs != nil {
			dst.Process.SupplementaryGIDs = append([]int(nil), src.Process.SupplementaryGIDs...)
			dst.Process.hasSupplementaryGIDs = true
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

func resolveHostPath(base, path string) string {
	path = expandHome(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

func validateConfig(cfg Config) error {
	if err := validateProcess(cfg.Process); err != nil {
		return err
	}
	if err := validateEnv(cfg.Env); err != nil {
		return err
	}
	for _, volume := range cfg.Volumes {
		if volume.Source == "" {
			return errors.New("volume.source is required")
		}
		if _, err := os.Stat(volume.Source); err != nil {
			return err
		}
		if !filepath.IsAbs(volume.Target) {
			return errors.New("volume.target must be absolute")
		}
		if volume.ReadOnly && volume.SyncBack {
			return errors.New("volume.sync_back cannot be true for read_only volumes")
		}
		switch volume.Ownership {
		case "", "host", "process":
		default:
			return errors.New("volume.ownership must be host or process")
		}
		if volume.Ownership == "process" && cfg.Process == nil {
			return errors.New("volume.ownership=process requires process.uid and process.gid")
		}
	}
	return nil
}

func validateProcess(process *ProcessConfig) error {
	if process == nil {
		return nil
	}
	switch {
	case process.hasUID != process.hasGID:
		return errors.New("process.uid and process.gid must both be set")
	case process.hasSupplementaryGIDs && (!process.hasUID || !process.hasGID):
		return errors.New("process.supplementary_gids requires process.uid and process.gid")
	case !process.hasUID && !process.hasGID && !process.hasSupplementaryGIDs:
		return errors.New("process.uid and process.gid must both be set")
	case process.hasUID && process.UID < 0:
		return errors.New("process.uid must be non-negative")
	case process.hasGID && process.GID < 0:
		return errors.New("process.gid must be non-negative")
	}
	for _, gid := range process.SupplementaryGIDs {
		if gid < 0 {
			return errors.New("process.supplementary_gids must be non-negative")
		}
	}
	return nil
}

func validateEnv(env EnvConfig) error {
	for key, entry := range env.FromCommand {
		switch {
		case len(entry.Command) == 0 && entry.Shell == "":
			return errors.New("env.from_command." + key + " must set command or shell")
		case len(entry.Command) > 0 && entry.Shell != "":
			return errors.New("env.from_command." + key + " must not set both command and shell")
		}
	}
	return nil
}
