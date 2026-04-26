package config

type Config struct {
	Image            string            `yaml:"image"`
	ImageCacheDir    string            `yaml:"image_cache_dir"`
	KernelPath       string            `yaml:"kernel_path"`
	DefaultResources ResourceConfig    `yaml:"default_resources"`
	Kernel           KernelConfig      `yaml:"kernel"`
	Resources        ResourceConfig    `yaml:"resources"`
	Workspace        WorkspaceConfig   `yaml:"workspace"`
	Volumes          []VolumeConfig    `yaml:"volumes"`
	Network          NetworkConfig     `yaml:"network"`
	Process          *ProcessConfig    `yaml:"process"`
	Features         []FeatureConfig   `yaml:"features"`
	Env              EnvConfig         `yaml:"env"`
	Command          []string          `yaml:"-"`
	Verbose          bool              `yaml:"-"`
	DryRun           bool              `yaml:"-"`
	RuntimeEnv       map[string]string `yaml:"-"`
}

type KernelConfig struct {
	Path string `yaml:"path"`
}

type ResourceConfig struct {
	VCPU     int `yaml:"vcpu"`
	MemoryMB int `yaml:"memory_mb"`
	DiskMB   int `yaml:"disk_mb"`
}

type WorkspaceConfig struct {
	Mount       string `yaml:"mount"`
	Target      string `yaml:"target"`
	SyncBack    bool   `yaml:"sync_back"`
	SyncDeletes bool   `yaml:"sync_deletes"`
	SyncConfirm bool   `yaml:"sync_confirm"`
}

type VolumeConfig struct {
	Source    string `yaml:"source"`
	Target    string `yaml:"target"`
	ReadOnly  bool   `yaml:"read_only"`
	SyncBack  bool   `yaml:"sync_back"`
	Ownership string `yaml:"ownership"`
}

type NetworkConfig struct {
	Mode         string     `yaml:"mode"`
	Audit        bool       `yaml:"audit"`
	DenyIfNoSNI  bool       `yaml:"deny_if_no_sni"`
	DNS          DNSConfig  `yaml:"dns"`
	TCP          TCPConfig  `yaml:"tcp"`
	TLS          TLSConfig  `yaml:"tls"`
	MITM         MITMConfig `yaml:"mitm"`
	HTTP         HTTPConfig `yaml:"http"`
	LogDecisions bool       `yaml:"-"`
}

type DNSConfig struct {
	Allowed []string `yaml:"allowed"`
	Denied  []string `yaml:"denied"`
}

type TCPConfig struct {
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
	DeniedCIDRs  []string `yaml:"denied_cidrs"`
}

type TLSConfig struct {
	AllowedSNI []string `yaml:"allowed_sni"`
	DeniedSNI  []string `yaml:"denied_sni"`
}

type MITMConfig struct {
	Enabled         bool             `yaml:"enabled"`
	Mode            string           `yaml:"mode"`
	OnUntrustedCert string           `yaml:"on_untrusted_cert"`
	LogRequests     bool             `yaml:"log_requests"`
	CA              MITMCAConfig     `yaml:"ca"`
	Bypass          MITMBypassConfig `yaml:"bypass"`
}

type MITMCAConfig struct {
	Name          string `yaml:"name"`
	InstallSystem bool   `yaml:"install_system"`
	InstallDocker bool   `yaml:"install_docker"`
}

type MITMBypassConfig struct {
	Hosts []string `yaml:"hosts"`
	SNI   []string `yaml:"sni"`
}

type HTTPConfig struct {
	Default string           `yaml:"default"`
	Rules   []HTTPRuleConfig `yaml:"rules"`
}

type HTTPRuleConfig struct {
	Action  string   `yaml:"action"`
	Host    string   `yaml:"host"`
	Methods []string `yaml:"methods"`
	Paths   []string `yaml:"paths"`
}

type ProcessConfig struct {
	UID               int   `yaml:"uid" json:"uid"`
	GID               int   `yaml:"gid" json:"gid"`
	SupplementaryGIDs []int `yaml:"supplementary_gids" json:"supplementary_gids,omitempty"`

	hasUID               bool `yaml:"-" json:"-"`
	hasGID               bool `yaml:"-" json:"-"`
	hasSupplementaryGIDs bool `yaml:"-" json:"-"`
}

type EnvConfig struct {
	Static      map[string]string     `yaml:"static"`
	FromHost    map[string]string     `yaml:"from_host"`
	FromCommand map[string]EnvCommand `yaml:"from_command"`
}

type EnvCommand struct {
	Command []string `yaml:"command"`
	Shell   string   `yaml:"shell"`
}

type FeatureConfig struct {
	Name   string         `yaml:"name"`
	Config map[string]any `yaml:"config"`
}
