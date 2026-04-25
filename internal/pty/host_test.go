package pty

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
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
