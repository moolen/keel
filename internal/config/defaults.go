package config

import (
	"os"
	"path/filepath"
)

func Default() Config {
	home, _ := os.UserHomeDir()
	return Config{
		Image:         "ubuntu:24.04",
		ImageCacheDir: filepath.Join(home, ".cache", "keel", "images"),
		Kernel: KernelConfig{
			Source: "release://latest",
		},
		Resources: ResourceConfig{
			VCPU:     2,
			MemoryMB: 2048,
			DiskMB:   4096,
		},
		DefaultResources: ResourceConfig{
			VCPU:     2,
			MemoryMB: 2048,
			DiskMB:   4096,
		},
		Workspace: WorkspaceConfig{
			Mount:       ".",
			Target:      "/workspace",
			SyncConfirm: true,
		},
		Network: NetworkConfig{
			Mode:  "vsock",
			Audit: false,
			TCP: TCPConfig{
				AllowedCIDRs: []string{},
				DeniedCIDRs:  []string{},
			},
			DNS: DNSConfig{
				Allowed: []string{},
				Denied:  []string{},
			},
			TLS: TLSConfig{
				AllowedSNI: []string{},
				DeniedSNI:  []string{},
			},
			MITM: MITMConfig{
				Mode:            "optional",
				OnUntrustedCert: "deny",
				Bypass: MITMBypassConfig{
					Hosts: []string{},
					SNI:   []string{},
				},
			},
			HTTP: HTTPConfig{
				Default: "deny",
				Rules:   []HTTPRuleConfig{},
			},
		},
		Env: EnvConfig{
			Static: map[string]string{
				"TERM": "xterm-256color",
			},
		},
	}
}
