//go:build linux

package hypervisor

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
)

func TestDialVSockPreservesPayloadAfterAck(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "firecracker.vsock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, len("CONNECT 1000\n"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- err
			return
		}
		if got, want := string(buf), "CONNECT 1000\n"; got != want {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("OK 52\n\x03\x00"))
		done <- err
	}()

	conn, err := dialVSock(context.Background(), socketPath, 1000)
	if err != nil {
		t.Fatalf("dialVSock() error = %v", err)
	}
	defer conn.Close()

	frame := make([]byte, 2)
	if _, err := io.ReadFull(conn, frame); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if got, want := string(frame), "\x03\x00"; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if err := <-done; err != nil {
		t.Fatalf("server error = %v", err)
	}
}
