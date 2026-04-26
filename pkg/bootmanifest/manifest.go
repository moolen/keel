package bootmanifest

type Manifest struct {
	Command []string          `json:"command,omitempty"`
	CWD     string            `json:"cwd,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Process *ProcessConfig    `json:"process,omitempty"`
	Volumes []VolumeMount     `json:"volumes,omitempty"`
}

type ProcessConfig struct {
	UID               int   `json:"uid"`
	GID               int   `json:"gid"`
	SupplementaryGIDs []int `json:"supplementary_gids,omitempty"`
}

type VolumeMount struct {
	Device    string `json:"device"`
	Target    string `json:"target"`
	Kind      string `json:"kind"`
	Subpath   string `json:"subpath,omitempty"`
	ReadOnly  bool   `json:"read_only,omitempty"`
	SyncBack  bool   `json:"sync_back,omitempty"`
	Ownership string `json:"ownership,omitempty"`
}
