package pty

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/moolen/keel/internal/vsock"
)

func TestClientRetriesDialUntilGuestPTYIsReady(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()

	server, client := net.Pipe()
	defer server.Close()

	attempts := 0
	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() {
		defer client.Close()
		done <- vsock.WriteExitFrame(client, 0)
	}()

	runErr := (Client{
		SocketPath: "ignored",
		Stdin:      stdin,
		Stdout:     &stdout,
		RetryDelay: time.Millisecond,
		Dial: func(context.Context, string, uint32) (net.Conn, error) {
			attempts++
			if attempts < 3 {
				return nil, errors.New("connect: connection refused")
			}
			return server, nil
		},
	}).Run(context.Background())
	if err := <-done; err != nil {
		t.Fatalf("WriteExitFrame() error = %v", err)
	}
	if runErr != nil {
		t.Fatalf("Run() error = %v", runErr)
	}
	if attempts != 3 {
		t.Fatalf("dial attempts = %d, want 3", attempts)
	}
}

func TestClientForwardsHostSignalsToGuest(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()

	server, client := net.Pipe()
	defer server.Close()

	var signalCh chan<- os.Signal
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- (Client{
			SocketPath: "ignored",
			Stdin:      stdin,
			Stdout:     &bytes.Buffer{},
			Dial: func(context.Context, string, uint32) (net.Conn, error) {
				return client, nil
			},
			NotifySignals: func(ch chan<- os.Signal, _ ...os.Signal) {
				signalCh = ch
			},
			StopSignals: func(chan<- os.Signal) {},
		}).Run(context.Background())
	}()

	deadline := time.Now().Add(time.Second)
	for signalCh == nil {
		if time.Now().After(deadline) {
			t.Fatal("signal channel was not registered")
		}
		time.Sleep(time.Millisecond)
	}

	signalCh <- syscall.SIGTERM
	frame, err := vsock.ReadFrame(server)
	if err != nil {
		t.Fatalf("ReadFrame(signal) error = %v", err)
	}
	if frame.Type != vsock.MessageSignal || frame.Signal != byte(syscall.SIGTERM) {
		t.Fatalf("signal frame = %#v", frame)
	}
	if err := vsock.WriteExitFrame(server, 0); err != nil {
		t.Fatalf("WriteExitFrame() error = %v", err)
	}
	if err := <-runErrCh; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestClientReturnsExitCodeError(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer stdin.Close()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- vsock.WriteExitFrame(client, 42)
	}()

	err = (Client{
		SocketPath: "ignored",
		Stdin:      stdin,
		Stdout:     &bytes.Buffer{},
		Dial: func(context.Context, string, uint32) (net.Conn, error) {
			return server, nil
		},
	}).Run(context.Background())
	if writeErr := <-done; writeErr != nil {
		t.Fatalf("WriteExitFrame() error = %v", writeErr)
	}
	if err == nil {
		t.Fatal("Run() error = nil, want exit status error")
	}
	var exitErr interface{ ExitCode() int }
	if !errors.As(err, &exitErr) {
		t.Fatalf("Run() error = %T, want error with ExitCode", err)
	}
	if got, want := exitErr.ExitCode(), 42; got != want {
		t.Fatalf("ExitCode() = %d, want %d", got, want)
	}
}
