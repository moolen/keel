package vm

import (
	"fmt"
	"os"
	"os/exec"
)

type kvmAccessHelper struct {
	open func(string) (*os.File, error)
	fix  func() error
}

func ensureKVMAccess() error {
	helper := kvmAccessHelper{
		open: func(path string) (*os.File, error) {
			return os.OpenFile(path, os.O_RDWR, 0)
		},
		fix: repairKVMAccess,
	}
	return helper.ensure()
}

func (h kvmAccessHelper) ensure() error {
	open := h.open
	if open == nil {
		open = func(path string) (*os.File, error) {
			return os.OpenFile(path, os.O_RDWR, 0)
		}
	}
	file, err := open("/dev/kvm")
	if err == nil {
		file.Close()
		return nil
	}
	if !os.IsPermission(err) {
		if os.IsNotExist(err) {
			return fmt.Errorf("kvm unavailable: /dev/kvm is missing; enable hardware virtualization and KVM on the host")
		}
		return fmt.Errorf("kvm unavailable: %w", err)
	}

	fix := h.fix
	if fix == nil {
		fix = repairKVMAccess
	}
	if err := fix(); err != nil {
		return fmt.Errorf("repair /dev/kvm access: %w. Keel needs read/write access to /dev/kvm", err)
	}

	file, err = open("/dev/kvm")
	if err != nil {
		return fmt.Errorf("kvm unavailable after repair: %w. verify that your user can open /dev/kvm", err)
	}
	return file.Close()
}

func repairKVMAccess() error {
	user := os.Getenv("USER")
	if user == "" {
		return fmt.Errorf("USER is not set")
	}
	cmd := exec.Command("sudo", "setfacl", "-m", fmt.Sprintf("u:%s:rw", user), "/dev/kvm")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, output)
	}
	return nil
}
