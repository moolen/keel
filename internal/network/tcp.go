package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

type TCPProxy struct {
	Policy      *PolicyEngine
	DialContext func(context.Context, string, string) (net.Conn, error)
	Now         func() time.Time
}

func (p TCPProxy) Serve(ctx context.Context, vsockPath string) error {
	socketPath := filepath.Clean(vsockPath) + "_3128"
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return err
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			if err := p.handleConn(ctx, conn); err != nil && ctx.Err() == nil {
				log.Printf("tcp proxy connection error: %v", err)
			}
		}()
	}
}

func (p TCPProxy) handleConn(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	destination, err := readDestinationHeader(conn)
	if err != nil {
		return err
	}
	ip, port, err := parseDestination(destination)
	if err != nil {
		return err
	}

	preface := []byte(nil)
	sni := ""
	if port == 443 {
		preface, sni, err = readTLSClientPreface(conn)
		if err != nil {
			return err
		}
	}

	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	decision := p.Policy.EvaluateTCP(ip, port, sni, now)
	if !decision.Allowed {
		log.Printf("tcp denied destination=%s sni=%s rule=%s reason=%s", destination, sni, decision.Rule, decision.Reason)
		return nil
	}
	log.Printf("tcp allowed destination=%s sni=%s rule=%s reason=%s", destination, sni, decision.Rule, decision.Reason)

	dialContext := p.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	upstream, err := dialContext(ctx, "tcp", destination)
	if err != nil {
		return err
	}
	defer upstream.Close()

	if len(preface) > 0 {
		if _, err := upstream.Write(preface); err != nil {
			return err
		}
	}

	return bridgeTCP(conn, upstream)
}

func parseDestination(destination string) (net.IP, int, error) {
	host, portValue, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("destination host %q is not an IP address", host)
	}
	port, err := net.LookupPort("tcp", portValue)
	if err != nil {
		return nil, 0, err
	}
	return ip, port, nil
}

func readTLSClientPreface(conn net.Conn) ([]byte, string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, "", err
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, "", err
	}
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	body := make([]byte, recordLength)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, "", err
	}
	data := append(header, body...)
	sni, err := ParseClientHelloSNI(data)
	if err != nil {
		return data, "", nil
	}
	return data, sni, nil
}

func bridgeTCP(client, upstream net.Conn) error {
	errCh := make(chan error, 2)

	go copyTCP(errCh, upstream, client)
	go copyTCP(errCh, client, upstream)

	var firstErr error
	for range 2 {
		err := <-errCh
		if firstErr == nil && !isIgnorableProxyError(err) {
			firstErr = err
		}
	}
	return firstErr
}

func copyTCP(errCh chan<- error, dst net.Conn, src net.Conn) {
	_, err := io.Copy(dst, src)
	closeWrite(dst)
	errCh <- err
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func isIgnorableProxyError(err error) bool {
	return err == nil || err == io.EOF || err == net.ErrClosed
}

func readDestinationHeader(r io.Reader) (string, error) {
	var length [1]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return "", err
	}
	buf := make([]byte, int(length[0]))
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func writeDestinationHeader(w io.Writer, destination string) error {
	if len(destination) > 0xff {
		return fmt.Errorf("destination header too large: %d", len(destination))
	}
	if _, err := w.Write([]byte{byte(len(destination))}); err != nil {
		return err
	}
	_, err := io.WriteString(w, destination)
	return err
}
