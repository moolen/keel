package pty

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	fcvsock "github.com/firecracker-microvm/firecracker-go-sdk/vsock"
	"github.com/moolen/keel/internal/vsock"
	"golang.org/x/term"
)

type Client struct {
	SocketPath   string
	Stdin        *os.File
	Stdout       io.Writer
	Dial         func(context.Context, string, uint32) (net.Conn, error)
	RetryTimeout time.Duration
	RetryDelay   time.Duration
}

func (c Client) Run(ctx context.Context) error {
	stdin := c.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := c.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}

	conn, err := c.dialPTY(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	restore, err := makeRaw(stdin)
	if err != nil {
		return err
	}
	defer restore()

	if err := sendResize(conn, stdin); err != nil && !isTerminal(stdin) {
		return err
	}

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)

	go func() {
		for range winch {
			_ = sendResize(conn, stdin)
		}
	}()
	if isTerminal(stdin) {
		winch <- syscall.SIGWINCH
	}

	go forwardInput(conn, stdin)

	for {
		frame, err := vsock.ReadFrame(conn)
		if err != nil {
			return err
		}
		switch frame.Type {
		case vsock.MessageData:
			if _, err := stdout.Write(frame.Data); err != nil {
				return err
			}
		case vsock.MessageExit:
			if frame.Code == 0 {
				return nil
			}
			return fmt.Errorf("command exited with code %d", frame.Code)
		}
	}
}

func (c Client) dialPTY(ctx context.Context) (net.Conn, error) {
	dial := c.Dial
	if dial == nil {
		dial = func(ctx context.Context, path string, port uint32) (net.Conn, error) {
			return fcvsock.DialContext(ctx, path, port)
		}
	}
	retryTimeout := c.RetryTimeout
	if retryTimeout <= 0 {
		retryTimeout = 5 * time.Second
	}
	retryDelay := c.RetryDelay
	if retryDelay <= 0 {
		retryDelay = 50 * time.Millisecond
	}
	deadline := time.Now().Add(retryTimeout)
	var lastErr error
	for {
		conn, err := dial(ctx, c.SocketPath, vsock.PortPTY)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelay):
		}
	}
}

func forwardInput(w io.Writer, stdin *os.File) {
	buf := make([]byte, 32*1024)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			_ = vsock.WriteDataFrame(w, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func sendResize(w io.Writer, file *os.File) error {
	if !isTerminal(file) {
		return nil
	}
	width, height, err := term.GetSize(int(file.Fd()))
	if err != nil {
		return err
	}
	return vsock.WriteResizeFrame(w, uint16(height), uint16(width))
}

func makeRaw(file *os.File) (func(), error) {
	if !isTerminal(file) {
		return func() {}, nil
	}
	state, err := term.MakeRaw(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	return func() {
		_ = term.Restore(int(file.Fd()), state)
	}, nil
}

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}
