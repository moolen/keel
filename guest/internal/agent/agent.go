package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	guestinternal "github.com/moolen/keel/guest/internal"
	guestfeatures "github.com/moolen/keel/guest/internal/features"
	pkgboot "github.com/moolen/keel/pkg/bootmanifest"
)

type bootConfig struct {
	Command        []string
	WorkDir        string
	Features       []guestfeatures.ConfiguredFeature
	Process        *processConfig
	Env            map[string]string
	Volumes        []volumeMount
	MetadataDevice string
}

type processConfig = guestinternal.ProcessConfig

type volumeMount struct {
	Device    string
	Target    string
	Kind      string
	Subpath   string
	ReadOnly  bool
	Ownership string
}

type initOps struct {
	chdir      func(string) error
	runCommand func(bootConfig, []string) error
	powerOff   func() error
}

type bootOps struct {
	loadBootConfig       func() (bootConfig, error)
	mountCoreFilesystems func() error
	mountWorkspace       func(string) error
	mountVolumes         func([]volumeMount, *processConfig) error
	attachConsole        func() error
	runInit              func(bootConfig, initOps) error
	initOps              initOps
}

func Run() error {
	return boot(bootOps{
		loadBootConfig:       loadBootConfig,
		mountCoreFilesystems: mountCoreFilesystems,
		mountWorkspace:       mountWorkspace,
		mountVolumes:         mountVolumes,
		attachConsole:        attachConsole,
		runInit:              runInit,
		initOps: initOps{
			chdir:      os.Chdir,
			runCommand: runCommand,
			powerOff:   powerOff,
		},
	})
}

func boot(ops bootOps) error {
	if err := ops.mountCoreFilesystems(); err != nil {
		return err
	}
	cfg, err := ops.loadBootConfig()
	if err != nil {
		return err
	}
	if err := ops.mountWorkspace(cfg.WorkDir); err != nil {
		return err
	}
	if err := ops.mountVolumes(cfg.Volumes, cfg.Process); err != nil {
		return err
	}
	if err := ops.attachConsole(); err != nil {
		return err
	}
	return ops.runInit(cfg, ops.initOps)
}

func loadBootConfig() (bootConfig, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return bootConfig{}, err
	}
	cfg, err := parseKernelCommandLine(strings.TrimSpace(string(data)))
	if err != nil {
		return bootConfig{}, err
	}
	if cfg.MetadataDevice == "" {
		return cfg, nil
	}
	manifest, err := guestinternal.LoadBootManifest(cfg.MetadataDevice)
	if err != nil {
		return bootConfig{}, err
	}
	applyBootManifest(&cfg, manifest)
	return cfg, nil
}

func parseKernelCommandLine(cmdline string) (bootConfig, error) {
	cfg := bootConfig{
		WorkDir: "/workspace",
	}
	for _, field := range strings.Fields(cmdline) {
		switch {
		case strings.HasPrefix(field, "keel.cmd="):
			encoded := strings.TrimPrefix(field, "keel.cmd=")
			data, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				return bootConfig{}, err
			}
			if err := json.Unmarshal(data, &cfg.Command); err != nil {
				return bootConfig{}, err
			}
		case strings.HasPrefix(field, "keel.cwd="):
			cfg.WorkDir = strings.TrimPrefix(field, "keel.cwd=")
		case strings.HasPrefix(field, "keel.features="):
			encoded := strings.TrimPrefix(field, "keel.features=")
			data, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				return bootConfig{}, err
			}
			if err := json.Unmarshal(data, &cfg.Features); err != nil {
				return bootConfig{}, err
			}
		case strings.HasPrefix(field, "keel.process="):
			encoded := strings.TrimPrefix(field, "keel.process=")
			data, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				return bootConfig{}, err
			}
			cfg.Process = &processConfig{}
			if err := json.Unmarshal(data, cfg.Process); err != nil {
				return bootConfig{}, err
			}
		case strings.HasPrefix(field, "keel.meta="):
			cfg.MetadataDevice = strings.TrimPrefix(field, "keel.meta=")
		}
	}
	return cfg, nil
}

func applyBootManifest(cfg *bootConfig, manifest pkgboot.Manifest) {
	if len(manifest.Command) > 0 {
		cfg.Command = append([]string(nil), manifest.Command...)
	}
	if manifest.CWD != "" {
		cfg.WorkDir = manifest.CWD
	}
	if len(manifest.Env) > 0 {
		cfg.Env = make(map[string]string, len(manifest.Env))
		for key, value := range manifest.Env {
			cfg.Env[key] = value
		}
	}
	if manifest.Process != nil {
		cfg.Process = &processConfig{
			UID:               manifest.Process.UID,
			GID:               manifest.Process.GID,
			SupplementaryGIDs: append([]int(nil), manifest.Process.SupplementaryGIDs...),
		}
	}
	if len(manifest.Features) > 0 {
		cfg.Features = make([]guestfeatures.ConfiguredFeature, 0, len(manifest.Features))
		for _, feature := range manifest.Features {
			cfg.Features = append(cfg.Features, guestfeatures.ConfiguredFeature{
				Name:   feature.Name,
				Config: cloneAnyMap(feature.Config),
			})
		}
	}
	if len(manifest.Volumes) > 0 {
		cfg.Volumes = make([]volumeMount, 0, len(manifest.Volumes))
		for _, item := range manifest.Volumes {
			cfg.Volumes = append(cfg.Volumes, volumeMount{
				Device:    item.Device,
				Target:    item.Target,
				Kind:      item.Kind,
				Subpath:   item.Subpath,
				ReadOnly:  item.ReadOnly,
				Ownership: item.Ownership,
			})
		}
	}
}

func cloneAnyMap(items map[string]any) map[string]any {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]any, len(items))
	for key, value := range items {
		out[key] = value
	}
	return out
}

func mountCoreFilesystems() error {
	for _, dir := range []string{"/proc", "/sys", "/sys/fs/cgroup", "/dev", "/dev/pts", "/run", "/tmp"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	for _, mount := range coreMounts() {
		if err := syscall.Mount(mount.source, mount.target, mount.fstype, mount.flags, mount.data); err != nil && err != syscall.EBUSY {
			return err
		}
	}
	if err := ensurePTMXSymlink(); err != nil {
		return err
	}
	return nil
}

type coreMount struct {
	source string
	target string
	fstype string
	flags  uintptr
	data   string
}

func coreMounts() []coreMount {
	return []coreMount{
		{"proc", "/proc", "proc", 0, ""},
		{"sysfs", "/sys", "sysfs", 0, ""},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", 0, ""},
		{"devtmpfs", "/dev", "devtmpfs", 0, "mode=0755"},
		{"devpts", "/dev/pts", "devpts", 0, "newinstance,ptmxmode=0666,mode=0620"},
		{"tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, "mode=1777"},
	}
}

func ensurePTMXSymlink() error {
	info, err := os.Lstat("/dev/ptmx")
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return nil
	case err == nil:
		if removeErr := os.Remove("/dev/ptmx"); removeErr != nil {
			return removeErr
		}
	case os.IsNotExist(err):
	default:
		return err
	}
	return os.Symlink("pts/ptmx", "/dev/ptmx")
}

func mountWorkspace(target string) error {
	if target == "" {
		target = "/workspace"
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	device := "/dev/vdb"
	var lastErr error
	for range 50 {
		if _, err := os.Stat(device); err == nil {
			lastErr = syscall.Mount(device, target, "ext4", 0, "")
			if lastErr == nil || lastErr == syscall.EBUSY {
				return nil
			}
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("mount workspace: %w", lastErr)
}

func mountVolumes(volumes []volumeMount, process *processConfig) error {
	if len(volumes) == 0 {
		return nil
	}
	if err := os.MkdirAll("/run/keel-volumes", 0o755); err != nil {
		return err
	}
	for i, volume := range volumes {
		flags := uintptr(0)
		if volume.ReadOnly {
			flags |= syscall.MS_RDONLY
		}
		switch volume.Kind {
		case "dir":
			if err := os.MkdirAll(volume.Target, 0o755); err != nil {
				return err
			}
			if err := syscall.Mount(volume.Device, volume.Target, "ext4", flags, ""); err != nil && err != syscall.EBUSY {
				return err
			}
			if err := applyVolumeOwnership(volume.Target, volume, process); err != nil {
				return err
			}
		case "file":
			stage := filepath.Join("/run/keel-volumes", fmt.Sprintf("volume-%02d", i))
			if err := os.MkdirAll(stage, 0o755); err != nil {
				return err
			}
			if err := syscall.Mount(volume.Device, stage, "ext4", flags, ""); err != nil && err != syscall.EBUSY {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(volume.Target), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(volume.Target, os.O_CREATE, 0o644)
			if err == nil {
				_ = file.Close()
			} else if !os.IsExist(err) {
				return err
			}
			source := filepath.Join(stage, volume.Subpath)
			if err := syscall.Mount(source, volume.Target, "", syscall.MS_BIND, ""); err != nil && err != syscall.EBUSY {
				return err
			}
			if err := applyVolumeOwnership(volume.Target, volume, process); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyVolumeOwnership(target string, volume volumeMount, process *processConfig) error {
	if volume.ReadOnly || volume.Ownership != "process" || process == nil {
		return nil
	}
	return os.Chown(target, process.UID, process.GID)
}

func attachConsole() error {
	consolePath := "/dev/console"
	if err := os.MkdirAll(filepath.Dir(consolePath), 0o755); err != nil {
		return err
	}
	fd, err := syscall.Open(consolePath, syscall.O_RDWR, 0)
	if err != nil {
		return err
	}
	for _, target := range []int{0, 1, 2} {
		if err := syscall.Dup2(fd, target); err != nil {
			_ = syscall.Close(fd)
			return err
		}
	}
	return syscall.Close(fd)
}

func runInit(cfg bootConfig, ops initOps) error {
	if cfg.WorkDir != "" {
		if err := ops.chdir(cfg.WorkDir); err != nil {
			return err
		}
	}
	if len(cfg.Command) == 0 {
		cfg.Command = []string{"/bin/sh"}
	}
	if err := ops.runCommand(cfg, guestinternal.EnvListFromMap(cfg.Env, os.Environ())); err != nil {
		return err
	}
	return ops.powerOff()
}

func runCommand(cfg bootConfig, env []string) error {
	return guestinternal.Bootstrap(cfg.Command, env, cfg.Features, cfg.Process)
}

func powerOff() error {
	syscall.Sync()
	return syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
}
