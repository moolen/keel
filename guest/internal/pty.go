package internal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
	"github.com/mdlayher/vsock"
)

const (
	messageData   byte = 0x01
	messageResize byte = 0x02
	messageExit   byte = 0x03
	messageSignal byte = 0x04
	portPTY            = 1000
)

func ServePTY(command []string, cwd string, env []string) error {
	listener, err := vsock.Listen(portPTY, nil)
	if err != nil {
		return err
	}
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = cwd
	cmd.Env = env

	ptyFile, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptyFile.Close()

	readErr := make(chan error, 1)
	writeErr := make(chan error, 1)

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := ptyFile.Read(buf)
			if n > 0 {
				if writeErr := writeDataFrame(conn, buf[:n]); writeErr != nil {
					readErr <- writeErr
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					readErr <- nil
					return
				}
				readErr <- err
				return
			}
		}
	}()

	go func() {
		writeErr <- handleControlFrames(conn, ptyFile, cmd.Process)
	}()

	waitErr := cmd.Wait()
	if err := <-readErr; err != nil && !isClosedConn(err) && !errors.Is(err, syscall.EIO) {
		return err
	}
	if err := writeExitFrame(conn, exitCode(waitErr)); err != nil && !isClosedConn(err) {
		return err
	}
	return waitErr
}

func handleControlFrames(conn net.Conn, ptyFile *os.File, process *os.Process) error {
	for {
		frame, err := readFrame(conn)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch frame.Type {
		case messageData:
			if _, err := ptyFile.Write(frame.Data); err != nil {
				return err
			}
		case messageResize:
			if err := pty.Setsize(ptyFile, &pty.Winsize{Rows: frame.Rows, Cols: frame.Cols}); err != nil {
				return err
			}
		case messageSignal:
			if process == nil {
				continue
			}
			if err := process.Signal(syscall.Signal(frame.Signal)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown frame type %d", frame.Type)
		}
	}
}

type frame struct {
	Type   byte
	Data   []byte
	Rows   uint16
	Cols   uint16
	Signal byte
}

func readFrame(r io.Reader) (frame, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return frame{}, err
	}
	out := frame{Type: typ[0]}
	switch typ[0] {
	case messageData:
		var length uint32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return frame{}, err
		}
		out.Data = make([]byte, int(length))
		if _, err := io.ReadFull(r, out.Data); err != nil {
			return frame{}, err
		}
	case messageResize:
		if err := binary.Read(r, binary.BigEndian, &out.Rows); err != nil {
			return frame{}, err
		}
		if err := binary.Read(r, binary.BigEndian, &out.Cols); err != nil {
			return frame{}, err
		}
	case messageSignal:
		var signal [1]byte
		if _, err := io.ReadFull(r, signal[:]); err != nil {
			return frame{}, err
		}
		out.Signal = signal[0]
	default:
		return frame{}, fmt.Errorf("unknown frame type %d", typ[0])
	}
	return out, nil
}

func writeDataFrame(w io.Writer, data []byte) error {
	if _, err := w.Write([]byte{messageData}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func writeExitFrame(w io.Writer, code byte) error {
	_, err := w.Write([]byte{messageExit, code})
	return err
}

func exitCode(err error) byte {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return 1
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		return byte(status.ExitStatus())
	}
	return 1
}

func isClosedConn(err error) bool {
	if err == nil {
		return false
	}
	return err == net.ErrClosed || errors.Is(err, io.EOF)
}
