package config

import (
	"errors"
	"net"
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
	Workspace mergePresenceWorkspaceConfig `yaml:"workspace"`
	Network   mergePresenceNetworkConfig   `yaml:"network"`
	Process   *mergePresenceProcessConfig  `yaml:"process"`
}

type mergePresenceWorkspaceConfig struct {
	SyncBack    *bool `yaml:"sync_back"`
	SyncDeletes *bool `yaml:"sync_deletes"`
	SyncConfirm *bool `yaml:"sync_confirm"`
}

type mergePresenceNetworkConfig struct {
	Audit     *bool                    `yaml:"audit"`
	Endpoints *[]EndpointConfig        `yaml:"endpoints"`
	IPRules   *[]IPRuleConfig          `yaml:"ip_rules"`
	MITM      *mergePresenceMITMConfig `yaml:"mitm"`

	OldDenyIfNoSNI *bool `yaml:"deny_if_no_sni"`
	OldDNS         any   `yaml:"dns"`
	OldTCP         any   `yaml:"tcp"`
	OldTLS         any   `yaml:"tls"`
	OldHTTP        any   `yaml:"http"`
}

type mergePresenceMITMConfig struct {
	CA *mergePresenceMITMCA `yaml:"ca"`

	OldEnabled         *bool   `yaml:"enabled"`
	OldMode            *string `yaml:"mode"`
	OldOnUntrustedCert *string `yaml:"on_untrusted_cert"`
	OldLogRequests     *bool   `yaml:"log_requests"`
	OldBypass          any     `yaml:"bypass"`
}

type mergePresenceMITMCA struct {
	Name          *string `yaml:"name"`
	InstallSystem *bool   `yaml:"install_system"`
	InstallDocker *bool   `yaml:"install_docker"`
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
	cfg.Kernel.Path = expandHome(cfg.Kernel.Path)
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
	if err := rejectOldNetworkFields(presenceCfg.Network); err != nil {
		return err
	}

	mergeConfig(cfg, fileCfg, presenceCfg)
	return nil
}

func rejectOldNetworkFields(p mergePresenceNetworkConfig) error {
	if p.OldDenyIfNoSNI != nil || p.OldDNS != nil || p.OldTCP != nil || p.OldTLS != nil || p.OldHTTP != nil {
		return errors.New("old network policy fields were removed; migrate to network.endpoints and network.ip_rules")
	}
	if p.MITM != nil && (p.MITM.OldEnabled != nil || p.MITM.OldMode != nil || p.MITM.OldOnUntrustedCert != nil || p.MITM.OldLogRequests != nil || p.MITM.OldBypass != nil) {
		return errors.New("old network MITM fields were removed; migrate policy decisions to network.endpoints and direct IP access to network.ip_rules")
	}
	return nil
}

func mergeConfig(dst *Config, src Config, presence mergePresenceConfig) {
	if src.Image != "" {
		dst.Image = src.Image
	}
	if src.ImageCacheDir != "" {
		dst.ImageCacheDir = src.ImageCacheDir
	}
	if src.Kernel.Path != "" {
		dst.Kernel.Path = src.Kernel.Path
		dst.Kernel.Source = ""
	}
	if src.Kernel.Source != "" {
		dst.Kernel.Source = src.Kernel.Source
		dst.Kernel.Path = ""
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
	if src.Resources.RootDiskMB != 0 {
		dst.Resources.RootDiskMB = src.Resources.RootDiskMB
	}
	if src.Workspace.Mount != "" {
		dst.Workspace.Mount = src.Workspace.Mount
	}
	if src.Workspace.Target != "" {
		dst.Workspace.Target = src.Workspace.Target
	}
	if presence.Workspace.SyncBack != nil {
		dst.Workspace.SyncBack = src.Workspace.SyncBack
	}
	if presence.Workspace.SyncDeletes != nil {
		dst.Workspace.SyncDeletes = src.Workspace.SyncDeletes
	}
	if presence.Workspace.SyncConfirm != nil {
		dst.Workspace.SyncConfirm = src.Workspace.SyncConfirm
	}
	if src.Network.Mode != "" {
		dst.Network.Mode = src.Network.Mode
	}
	if presence.Network.Audit != nil {
		dst.Network.Audit = src.Network.Audit
	}
	if presence.Network.Endpoints != nil {
		dst.Network.Endpoints = append([]EndpointConfig(nil), src.Network.Endpoints...)
	}
	if presence.Network.IPRules != nil {
		dst.Network.IPRules = append([]IPRuleConfig(nil), src.Network.IPRules...)
	}
	if presence.Network.MITM != nil {
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
	if err := validateNetwork(cfg.Network); err != nil {
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

func validateNetwork(network NetworkConfig) error {
	for _, endpoint := range network.Endpoints {
		if strings.TrimSpace(endpoint.Host) == "" {
			return errors.New("network.endpoints.host is required")
		}
		if !validEndpointHost(endpoint.Host) {
			return errors.New("network.endpoints.host must be a DNS host or leading wildcard host")
		}
		if endpoint.Port <= 0 || endpoint.Port > 65535 {
			return errors.New("network.endpoints.port must be between 1 and 65535")
		}
		mitmRequired := endpoint.MITM != nil && endpoint.MITM.Required
		if endpoint.HTTP != nil && !mitmRequired {
			return errors.New("network.endpoints.http requires network.endpoints.mitm.required")
		}
		if endpoint.HTTP != nil {
			if err := validateEndpointHTTP(*endpoint.HTTP); err != nil {
				return err
			}
		}
	}
	for _, rule := range network.IPRules {
		if strings.TrimSpace(rule.CIDR) == "" {
			return errors.New("network.ip_rules.cidr is required")
		}
		if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
			return errors.New("network.ip_rules.cidr must be a valid CIDR")
		}
		if rule.Port <= 0 || rule.Port > 65535 {
			return errors.New("network.ip_rules.port must be between 1 and 65535")
		}
	}
	return nil
}

func validEndpointHost(host string) bool {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" || trimmed != host {
		return false
	}
	if strings.ContainsAny(host, " \t\r\n/") || strings.Contains(host, "://") {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	if strings.HasPrefix(host, "*.") {
		host = strings.TrimPrefix(host, "*.")
	} else if strings.Contains(host, "*") {
		return false
	}
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validateEndpointHTTP(http EndpointHTTPConfig) error {
	switch http.Default {
	case "", "allow", "deny":
	default:
		return errors.New("network.endpoints.http.default must be allow or deny")
	}
	for _, rule := range http.Rules {
		switch rule.Action {
		case "allow", "deny":
		default:
			return errors.New("network.endpoints.http.rules.action must be allow or deny")
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
