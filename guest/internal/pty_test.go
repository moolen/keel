package internal

import (
	"os/exec"
	"reflect"
	"syscall"
	"testing"
)

func TestConfigureCommandCredentialLeavesSysProcAttrUnsetWhenProcessOmitted(t *testing.T) {
	cmd := exec.Command("/bin/sh")

	configureCommandCredential(cmd, nil)

	if cmd.SysProcAttr != nil {
		t.Fatalf("cmd.SysProcAttr = %#v, want nil", cmd.SysProcAttr)
	}
}

func TestConfigureCommandCredentialAppliesConfiguredCredential(t *testing.T) {
	cmd := exec.Command("/bin/sh")
	process := &ProcessConfig{
		UID:               1000,
		GID:               1001,
		SupplementaryGIDs: []int{27, 44},
	}

	configureCommandCredential(cmd, process)

	if cmd.SysProcAttr == nil {
		t.Fatal("cmd.SysProcAttr = nil, want non-nil")
	}
	if cmd.SysProcAttr.Credential == nil {
		t.Fatal("cmd.SysProcAttr.Credential = nil, want non-nil")
	}
	credential := cmd.SysProcAttr.Credential
	if got, want := credential.Uid, uint32(1000); got != want {
		t.Fatalf("credential.Uid = %d, want %d", got, want)
	}
	if got, want := credential.Gid, uint32(1001); got != want {
		t.Fatalf("credential.Gid = %d, want %d", got, want)
	}
	if got, want := credential.Groups, []uint32{27, 44}; !reflect.DeepEqual(got, want) {
		t.Fatalf("credential.Groups = %#v, want %#v", got, want)
	}
	if got, want := cmd.SysProcAttr, (&syscall.SysProcAttr{Credential: credential}); !reflect.DeepEqual(got, want) {
		t.Fatalf("cmd.SysProcAttr = %#v, want %#v", got, want)
	}
}
