package internal

import (
	"errors"
	"net"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/moolen/keel/internal/vsock"
)

func TestConfigureCommandCredentialLeavesSysProcAttrUnsetWhenProcessOmitted(t *testing.T) {
	cmd := exec.Command("/bin/sh")

	configureCommandCredential(cmd, nil, 0)

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

	configureCommandCredential(cmd, process, 0)

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

func TestConfigureCommandCredentialAddsWorkloadCgroupFD(t *testing.T) {
	cmd := exec.Command("/bin/sh")

	configureCommandCredential(cmd, nil, 42)

	if cmd.SysProcAttr == nil {
		t.Fatal("cmd.SysProcAttr = nil, want non-nil")
	}
	if !cmd.SysProcAttr.UseCgroupFD {
		t.Fatal("UseCgroupFD = false, want true")
	}
	if got, want := cmd.SysProcAttr.CgroupFD, 42; got != want {
		t.Fatalf("CgroupFD = %d, want %d", got, want)
	}
}

func TestWriteStartupFailureSendsMessageAndExitFrame(t *testing.T) {
	server, client := net.Pipe()
	defer func() {
		_ = server.Close()
		_ = client.Close()
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- writeStartupFailure(server, []string{"curl", "-v", "example.com"}, exec.ErrNotFound)
	}()

	frame, err := vsock.ReadFrame(client)
	if err != nil {
		t.Fatalf("ReadFrame(data) error = %v", err)
	}
	if got, want := frame.Type, vsock.MessageData; got != want {
		t.Fatalf("data frame type = %d, want %d", got, want)
	}
	if got := string(frame.Data); !strings.Contains(got, "curl") || !strings.Contains(got, "not found") {
		t.Fatalf("data frame = %q, want command-not-found message", got)
	}

	exitFrame, err := vsock.ReadFrame(client)
	if err != nil {
		t.Fatalf("ReadFrame(exit) error = %v", err)
	}
	if got, want := exitFrame.Type, vsock.MessageExit; got != want {
		t.Fatalf("exit frame type = %d, want %d", got, want)
	}
	if got, want := exitFrame.Code, byte(127); got != want {
		t.Fatalf("exit code = %d, want %d", got, want)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("writeStartupFailure() error = %v", err)
	}
}

func TestStartupExitCodeMapsCommandNotFoundTo127(t *testing.T) {
	if got, want := startupExitCode(exec.ErrNotFound), byte(127); got != want {
		t.Fatalf("startupExitCode(exec.ErrNotFound) = %d, want %d", got, want)
	}
}

func TestStartupExitCodeDefaultsTo1(t *testing.T) {
	if got, want := startupExitCode(errors.New("boom")), byte(1); got != want {
		t.Fatalf("startupExitCode(boom) = %d, want %d", got, want)
	}
}
