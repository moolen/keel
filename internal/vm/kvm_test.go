package vm

import (
	"errors"
	"os"
	"testing"
)

func TestEnsureKVMAccessRepairsPermissionError(t *testing.T) {
	attempts := 0
	helper := kvmAccessHelper{
		open: func(string) (*os.File, error) {
			attempts++
			if attempts == 1 {
				return nil, os.ErrPermission
			}
			file, err := os.CreateTemp(t.TempDir(), "kvm")
			if err != nil {
				t.Fatalf("CreateTemp() error = %v", err)
			}
			return file, nil
		},
		fix: func() error { return nil },
	}

	if err := helper.ensure(); err != nil {
		t.Fatalf("ensure() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestEnsureKVMAccessReturnsFixError(t *testing.T) {
	helper := kvmAccessHelper{
		open: func(string) (*os.File, error) { return nil, os.ErrPermission },
		fix:  func() error { return errors.New("no sudo") },
	}

	err := helper.ensure()
	if err == nil || err.Error() != "repair /dev/kvm access: no sudo. Keel needs read/write access to /dev/kvm" {
		t.Fatalf("ensure() error = %v", err)
	}
}

func TestEnsureKVMAccessReturnsMissingDeviceHint(t *testing.T) {
	helper := kvmAccessHelper{
		open: func(string) (*os.File, error) { return nil, os.ErrNotExist },
	}

	err := helper.ensure()
	if err == nil || err.Error() != "kvm unavailable: /dev/kvm is missing; enable hardware virtualization and KVM on the host" {
		t.Fatalf("ensure() error = %v", err)
	}
}
