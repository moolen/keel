package internal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

type ProcessConfig struct {
	UID               int   `json:"uid"`
	GID               int   `json:"gid"`
	SupplementaryGIDs []int `json:"supplementary_gids,omitempty"`
}

func ServePTY(command []string, cwd string, env []string, process *ProcessConfig, interception trafficInterception) error {
	listener, err := vsock.Listen(portPTY, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
	}()

	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()

	commandPath, err := resolveCommandPath(command[0], env)
	if err != nil {
		if writeErr := writeStartupFailure(conn, command, err); writeErr != nil && !isClosedConn(writeErr) {
			return writeErr
		}
		return err
	}
	cmd := exec.CommandContext(context.Background(), commandPath, command[1:]...)
	cmd.Dir = cwd
	cmd.Env = env
	configureCommandCredential(cmd, process, workloadCgroupFD(interception))
	if interception != nil {
		interception.attachCommand(cmd)
	}

	ptyFile, err := pty.Start(cmd)
	if err != nil {
		if writeErr := writeStartupFailure(conn, command, err); writeErr != nil && !isClosedConn(writeErr) {
			return writeErr
		}
		return err
	}
	defer func() {
		_ = ptyFile.Close()
	}()

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
	return writeCommandExit(conn, waitErr)
}

func writeCommandExit(conn net.Conn, waitErr error) error {
	if err := writeExitFrame(conn, exitCode(waitErr)); err != nil && !isClosedConn(err) {
		return err
	}
	return nil
}

func configureCommandCredential(cmd *exec.Cmd, process *ProcessConfig, cgroupFD int) {
	if process == nil && cgroupFD <= 0 {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	if cgroupFD > 0 {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = cgroupFD
	}
	if process == nil {
		return
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid:    uint32(process.UID),
		Gid:    uint32(process.GID),
		Groups: supplementaryGroups(process.SupplementaryGIDs),
	}
}

func workloadCgroupFD(interception trafficInterception) int {
	if interception == nil {
		return 0
	}
	return interception.workloadCgroupFD()
}

func supplementaryGroups(groups []int) []uint32 {
	if len(groups) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(groups))
	for _, gid := range groups {
		out = append(out, uint32(gid))
	}
	return out
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

func writeStartupFailure(w io.Writer, command []string, err error) error {
	message := formatStartupError(command, err)
	if message != "" {
		if writeErr := writeDataFrame(w, []byte(message)); writeErr != nil {
			return writeErr
		}
	}
	return writeExitFrame(w, startupExitCode(err))
}

func formatStartupError(command []string, err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, exec.ErrNotFound) {
		name := "command"
		if len(command) > 0 && command[0] != "" {
			name = command[0]
		}
		return fmt.Sprintf("%s: command not found\n", name)
	}
	text := err.Error()
	if strings.HasSuffix(text, "\n") {
		return text
	}
	return text + "\n"
}

func startupExitCode(err error) byte {
	if errors.Is(err, exec.ErrNotFound) {
		return 127
	}
	return 1
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

func resolveCommandPath(name string, env []string) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, nil
	}
	for _, entry := range env {
		if !strings.HasPrefix(entry, "PATH=") {
			continue
		}
		for _, dir := range filepath.SplitList(strings.TrimPrefix(entry, "PATH=")) {
			if dir == "" {
				continue
			}
			candidate := filepath.Join(dir, name)
			info, err := os.Stat(candidate)
			if err != nil || info.IsDir() {
				continue
			}
			if info.Mode()&0o111 == 0 {
				continue
			}
			return candidate, nil
		}
		break
	}
	return "", exec.ErrNotFound
}
