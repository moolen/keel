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
		KernelPath:    filepath.Join(home, ".cache", "keel", "kernel", "vmlinux"),
		Kernel: KernelConfig{
			Path: filepath.Join(home, ".cache", "keel", "kernel", "vmlinux"),
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
			Mode: "vsock",
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
				Bypass: MITMBypassConfig{
					Hosts: []string{},
					SNI:   []string{},
				},
			},
			HTTP: HTTPConfig{
				Rules: []HTTPRuleConfig{},
			},
		},
		Env: map[string]string{
			"TERM": "xterm-256color",
		},
	}
}
