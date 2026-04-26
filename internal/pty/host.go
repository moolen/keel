package pty

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	fcvsock "github.com/firecracker-microvm/firecracker-go-sdk/vsock"
	"github.com/moolen/keel/internal/vsock"
	"golang.org/x/term"
)

type Client struct {
	SocketPath    string
	Stdin         *os.File
	Stdout        io.Writer
	Dial          func(context.Context, string, uint32) (net.Conn, error)
	NotifySignals func(chan<- os.Signal, ...os.Signal)
	StopSignals   func(chan<- os.Signal)
	RetryTimeout  time.Duration
	RetryDelay    time.Duration
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
	defer func() {
		_ = conn.Close()
	}()
	writer := &frameWriter{writer: conn}

	restore, err := makeRaw(stdin)
	if err != nil {
		return err
	}
	defer restore()

	if err := sendResize(writer, stdin); err != nil && !isTerminal(stdin) {
		return err
	}

	signals := make(chan os.Signal, 4)
	notifySignals := c.NotifySignals
	if notifySignals == nil {
		notifySignals = signal.Notify
	}
	stopSignals := c.StopSignals
	if stopSignals == nil {
		stopSignals = signal.Stop
	}
	notifySignals(signals, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals(signals)

	go func() {
		for sig := range signals {
			switch sig {
			case syscall.SIGWINCH:
				_ = sendResize(writer, stdin)
			case syscall.SIGINT, syscall.SIGTERM:
				_ = writer.writeSignalFrame(byte(sig.(syscall.Signal)))
			}
		}
	}()
	if isTerminal(stdin) {
		signals <- syscall.SIGWINCH
	}

	go forwardInput(writer, stdin)

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

type frameWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *frameWriter) writeDataFrame(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return vsock.WriteDataFrame(w.writer, data)
}

func (w *frameWriter) writeResizeFrame(rows, cols uint16) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return vsock.WriteResizeFrame(w.writer, rows, cols)
}

func (w *frameWriter) writeSignalFrame(sig byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return vsock.WriteSignalFrame(w.writer, sig)
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

func forwardInput(w *frameWriter, stdin *os.File) {
	buf := make([]byte, 32*1024)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			_ = w.writeDataFrame(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func sendResize(w *frameWriter, file *os.File) error {
	if !isTerminal(file) {
		return nil
	}
	width, height, err := term.GetSize(int(file.Fd()))
	if err != nil {
		return err
	}
	return w.writeResizeFrame(uint16(height), uint16(width))
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
