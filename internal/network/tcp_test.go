package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTCPProxyAllowsCorrelatedDestination(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	summary := NewSummary()
	tracker.Observe("api.github.com", net.ParseIP("203.0.113.10"), 30*time.Second, time.Unix(100, 0))

	engine := NewPolicyEngine(PolicyConfig{}, tracker)

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	upstreamProxy, upstreamServer := net.Pipe()
	defer upstreamServer.Close()

	var mu sync.Mutex
	var dialNetwork string
	var dialAddress string

	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			dialNetwork = network
			dialAddress = address
			mu.Unlock()
			return upstreamProxy, nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	go func() {
		defer upstreamServer.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(upstreamServer, buf); err != nil {
			t.Errorf("upstream read error = %v", err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("upstream payload = %q, want ping", string(buf))
			return
		}
		if _, err := upstreamServer.Write([]byte("pong")); err != nil {
			t.Errorf("upstream write error = %v", err)
		}
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:80"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := clientSide.Write([]byte("ping")); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatalf("client read error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want pong", string(reply))
	}
	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}

	mu.Lock()
	defer mu.Unlock()
	if dialNetwork != "tcp" {
		t.Fatalf("dial network = %q, want tcp", dialNetwork)
	}
	if dialAddress != "203.0.113.10:80" {
		t.Fatalf("dial address = %q, want 203.0.113.10:80", dialAddress)
	}
	assertSummaryReportContains(t, summary, "tcp  api.github.com:80 policy=allowed count=1")
}

func TestTCPProxyDeniesUncorrelatedDestination(t *testing.T) {
	engine := NewPolicyEngine(PolicyConfig{}, NewTracker(60*time.Second))
	summary := NewSummary()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	var dialed bool
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, fmt.Errorf("unexpected dial")
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	if err := writeDestinationHeader(clientSide, "198.51.100.25:80"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
	if dialed {
		t.Fatal("dialer was called for denied destination")
	}
	assertSummaryReportContains(t, summary, "tcp  198.51.100.25:80 policy=denied count=1")
}

func TestTCPProxyDeniesMismatchedTLSSNI(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	summary := NewSummary()
	tracker.Observe("api.github.com", net.ParseIP("203.0.113.10"), 30*time.Second, time.Unix(100, 0))

	engine := NewPolicyEngine(PolicyConfig{
		TLS: RuleSet{
			Allowed: []string{"*.github.com"},
		},
		DenyIfNoSNI: true,
	}, tracker)

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	var dialed bool
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, fmt.Errorf("unexpected dial")
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:443"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := clientSide.Write(mustClientHelloBytesForTCP(t, "evil.github.com")); err != nil {
		t.Fatalf("client write error = %v", err)
	}
	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
	if dialed {
		t.Fatal("dialer was called for mismatched TLS SNI")
	}
	assertSummaryReportContains(t, summary, "tcp  evil.github.com:443 policy=denied count=1")
}

func TestTCPProxyLogsWouldDenyInAuditModeOnOwnLine(t *testing.T) {
	engine := NewPolicyEngine(PolicyConfig{
		Audit: true,
	}, NewTracker(60*time.Second))
	summary := NewSummary()
	var events bytes.Buffer

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Events:  NewEventLogger(&events),
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, fmt.Errorf("dial failed")
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	if err := writeDestinationHeader(clientSide, "198.51.100.25:80"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err == nil || err.Error() != "dial failed" {
			t.Fatalf("handleConn() error = %v, want dial failed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}

	got := events.String()
	if !strings.HasPrefix(got, "\n[keel:tcp] ") {
		t.Fatalf("events = %q, want newline-prefixed keel tcp log", got)
	}
	if !strings.Contains(got, "would_deny destination=198.51.100.25:80 sni= rule=default reason=tcp destination not correlated") {
		t.Fatalf("events = %q, want would_deny audit log", got)
	}
}

func mustClientHelloBytesForTCP(t *testing.T, serverName string) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	payload := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		buf := make([]byte, 4096)
		n, err := serverConn.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		payload <- append([]byte(nil), buf[:n]...)
	}()

	go func() {
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		}
		_ = tls.Client(clientConn, cfg).Handshake()
	}()

	select {
	case data := <-payload:
		return data
	case err := <-errCh:
		t.Fatalf("failed to capture ClientHello: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ClientHello")
	}

	return nil
}
