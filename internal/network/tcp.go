package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const initialProxyInspectionTimeout = 10 * time.Second

type TCPProxy struct {
	Policy      *PolicyEngine
	DialContext func(context.Context, string, string) (net.Conn, error)
	MITM        *MITMProxy
	Summary     *Summary
	Events      *EventLogger
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
	return p.ServeListener(ctx, listener)
}

func (p TCPProxy) ServeListener(ctx context.Context, listener net.Listener) error {
	defer func() {
		_ = listener.Close()
	}()

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
				p.Events.Printf("tcp", "proxy_error err=%v", err)
			}
		}()
	}
}

func (p TCPProxy) handleConn(ctx context.Context, conn net.Conn) error {
	defer func() {
		_ = conn.Close()
	}()

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
	inspectErr := error(nil)
	if port == 443 {
		preface, sni, inspectErr, err = readTLSClientPreface(conn)
		if err != nil {
			return err
		}
	}

	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	decision := p.Policy.EvaluateTCP(ip, port, sni, now)
	if decision.Allowed && port == 443 && p.MITM != nil && p.MITM.Enabled && tlsInspectionRequired(preface, sni, inspectErr) {
		decision = Decision{Reason: "mitm inspection required but client hello parsing failed", Rule: "mitm"}
	}
	p.Summary.RecordTCP(summaryHost(p.Policy, ip, sni, now), port, decision)
	if !decision.Allowed {
		p.Events.Printf("tcp", "%s destination=%s sni=%s rule=%s reason=%s", decisionLabel(decision), destination, sni, decision.Rule, decision.Reason)
		return nil
	}
	p.Events.Printf("tcp", "%s destination=%s sni=%s rule=%s reason=%s", decisionLabel(decision), destination, sni, decision.Rule, decision.Reason)

	if p.MITM != nil && port == 80 && p.MITM.Enabled {
		httpPreface, host, isHTTP, err := readHTTPPreface(conn)
		if err != nil {
			return err
		}
		if isHTTP && !matchesAnyHostPattern(host, p.MITM.BypassHosts) {
			return p.MITM.HandleHTTP(ctx, &prefixedConn{
				Conn:   conn,
				prefix: bytes.NewReader(httpPreface),
			}, destination)
		}
		preface = httpPreface
	}

	if p.MITM != nil && port == 443 && len(preface) > 0 && sni != "" && p.MITM.EnabledFor(sni) {
		return p.MITM.HandleTLS(ctx, &prefixedConn{
			Conn:   conn,
			prefix: bytes.NewReader(preface),
		}, sni, destination)
	}

	dialContext := p.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	upstream, err := dialContext(ctx, "tcp", destination)
	if err != nil {
		return err
	}
	defer func() {
		_ = upstream.Close()
	}()

	if len(preface) > 0 {
		if _, err := upstream.Write(preface); err != nil {
			return err
		}
	}

	return bridgeTCP(conn, upstream)
}

func summaryHost(policy *PolicyEngine, ip net.IP, sni string, now time.Time) string {
	if name := normalizeName(sni); name != "" {
		return name
	}
	if policy != nil && policy.tracker != nil {
		if domains := policy.tracker.Domains(ip, now); len(domains) > 0 {
			return domains[0]
		}
	}
	if ip != nil {
		return ip.String()
	}
	return "unknown"
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

func readTLSClientPreface(conn net.Conn) ([]byte, string, error, error) {
	if err := conn.SetReadDeadline(time.Now().Add(initialProxyInspectionTimeout)); err != nil {
		return nil, "", nil, err
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, "", nil, err
	}
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	body := make([]byte, recordLength)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, "", nil, err
	}
	data := append(header, body...)
	sni, parseErr := parseClientHelloSNI(data)
	return data, sni, parseErr, nil
}

func parseClientHelloSNI(data []byte) (sni string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("parse tls client hello: %v", recovered)
			sni = ""
		}
	}()
	sni, err = ParseClientHelloSNI(data)
	if err != nil && isIncompleteClientHelloError(err) {
		return "", errIncompleteClientHello
	}
	if err != nil && (err.Error() == "sni extension not present" || err.Error() == "host_name entry not present") {
		return "", errNoSNIExtension
	}
	return sni, err
}

func tlsInspectionRequired(preface []byte, sni string, parseErr error) bool {
	if parseErr == nil || sni != "" || !looksLikeTLSHandshakeRecord(preface) {
		return false
	}
	if errors.Is(parseErr, errIncompleteClientHello) {
		return false
	}
	return !errors.Is(parseErr, errNoSNIExtension)
}

func looksLikeTLSHandshakeRecord(preface []byte) bool {
	return len(preface) >= 5 && preface[0] == 0x16 && preface[1] == 0x03
}

var errNoSNIExtension = errors.New("sni extension not present")
var errIncompleteClientHello = errors.New("incomplete client hello")

func isIncompleteClientHelloError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "truncated")
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

func readHTTPPreface(conn net.Conn) ([]byte, string, bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(initialProxyInspectionTimeout)); err != nil {
		return nil, "", false, err
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	reader := bufio.NewReader(conn)
	var preface bytes.Buffer
	tee := io.TeeReader(io.LimitReader(reader, 32<<10), &preface)
	req, err := http.ReadRequest(bufio.NewReader(tee))
	if err != nil {
		if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "malformed HTTP request") {
			return preface.Bytes(), "", false, nil
		}
		return nil, "", false, err
	}
	closeRequestBody(req)
	return preface.Bytes(), normalizeHTTPHost(req.Host), true, nil
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

type prefixedConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if c.prefix != nil && c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}
