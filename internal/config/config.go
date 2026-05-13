package config

type Config struct {
	Image         string            `yaml:"image"`
	ImageCacheDir string            `yaml:"image_cache_dir"`
	Kernel        KernelConfig      `yaml:"kernel"`
	Resources     ResourceConfig    `yaml:"resources"`
	Workspace     WorkspaceConfig   `yaml:"workspace"`
	Volumes       []VolumeConfig    `yaml:"volumes"`
	Network       NetworkConfig     `yaml:"network"`
	Process       *ProcessConfig    `yaml:"process"`
	Features      []FeatureConfig   `yaml:"features"`
	Env           EnvConfig         `yaml:"env"`
	Command       []string          `yaml:"-"`
	Verbose       bool              `yaml:"-"`
	DryRun        bool              `yaml:"-"`
	RuntimeEnv    map[string]string `yaml:"-"`
}

type KernelConfig struct {
	Path   string `yaml:"path,omitempty"`
	Source string `yaml:"source,omitempty"`
}

type ResourceConfig struct {
	VCPU       int `yaml:"vcpu"`
	MemoryMB   int `yaml:"memory_mb"`
	DiskMB     int `yaml:"disk_mb"`
	RootDiskMB int `yaml:"root_disk_mb,omitempty"`
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
	Mode      string           `yaml:"mode"`
	Audit     bool             `yaml:"audit"`
	Endpoints []EndpointConfig `yaml:"endpoints"`
	IPRules   []IPRuleConfig  `yaml:"ip_rules"`
	MITM      MITMConfig      `yaml:"mitm"`

	LogDecisions bool `yaml:"-"`
}

type EndpointConfig struct {
	Host string              `yaml:"host"`
	Port int                 `yaml:"port"`
	TLS  *EndpointTLSConfig  `yaml:"tls,omitempty"`
	MITM *EndpointMITMConfig `yaml:"mitm,omitempty"`
	HTTP *EndpointHTTPConfig `yaml:"http,omitempty"`
}

type EndpointTLSConfig struct {
	RequireSNIMatch bool `yaml:"require_sni_match"`
}

type EndpointMITMConfig struct {
	Required bool `yaml:"required"`
}

type EndpointHTTPConfig struct {
	Default string                   `yaml:"default"`
	Rules   []EndpointHTTPRuleConfig `yaml:"rules"`
}

type EndpointHTTPRuleConfig struct {
	Action  string   `yaml:"action"`
	Methods []string `yaml:"methods"`
	Paths   []string `yaml:"paths"`
}

type IPRuleConfig struct {
	CIDR string `yaml:"cidr"`
	Port int    `yaml:"port"`
}

type MITMConfig struct {
	CA MITMCAConfig `yaml:"ca"`
}

type MITMCAConfig struct {
	Name          string `yaml:"name"`
	InstallSystem bool   `yaml:"install_system"`
	InstallDocker bool   `yaml:"install_docker"`
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
