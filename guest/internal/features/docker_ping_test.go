package features

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerDaemonReadyPingsUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
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

		reader := bufio.NewReader(conn)
		var request strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			request.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		if !strings.Contains(request.String(), "GET /_ping HTTP/1.0") {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		done <- err
	}()

	if err := dockerDaemonReady(socketPath); err != nil {
		t.Fatalf("dockerDaemonReady() error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server error = %v", err)
	}
}
