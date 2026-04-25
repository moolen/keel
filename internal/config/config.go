package config

type Config struct {
	Image            string            `yaml:"image"`
	ImageCacheDir    string            `yaml:"image_cache_dir"`
	KernelPath       string            `yaml:"kernel_path"`
	DefaultResources ResourceConfig    `yaml:"default_resources"`
	Kernel           KernelConfig      `yaml:"kernel"`
	Resources        ResourceConfig    `yaml:"resources"`
	Workspace        WorkspaceConfig   `yaml:"workspace"`
	Network          NetworkConfig     `yaml:"network"`
	Features         []FeatureConfig   `yaml:"features"`
	Env              map[string]string `yaml:"env"`
	Command          []string          `yaml:"-"`
	Verbose          bool              `yaml:"-"`
	DryRun           bool              `yaml:"-"`
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

type NetworkConfig struct {
	Mode         string    `yaml:"mode"`
	DenyIfNoSNI  bool      `yaml:"deny_if_no_sni"`
	DNS          DNSConfig `yaml:"dns"`
	TCP          TCPConfig `yaml:"tcp"`
	TLS          TLSConfig `yaml:"tls"`
	LogDecisions bool      `yaml:"-"`
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

type FeatureConfig struct {
	Name   string         `yaml:"name"`
	Config map[string]any `yaml:"config"`
}
