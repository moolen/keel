package network

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func TestTCPProxyPeeksTLSSNIOnNonStandardPort(t *testing.T) {
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

	// Use a non-standard TLS port (8443) — SNI must still be extracted.
	if err := writeDestinationHeader(clientSide, "203.0.113.10:8443"); err != nil {
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
		t.Fatal("dialer was called for mismatched TLS SNI on non-standard port")
	}
	assertSummaryReportContains(t, summary, "tcp  evil.github.com:8443 policy=denied count=1")
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
	if !strings.HasPrefix(got, "\r\x1b[2K[keel:tcp] ") {
		t.Fatalf("events = %q, want line-clearing keel tcp log", got)
	}
	if !strings.Contains(got, "would_deny destination=198.51.100.25:80 sni= rule=default reason=tcp destination not correlated") {
		t.Fatalf("events = %q, want would_deny audit log", got)
	}
}

func TestTCPProxyHandlesConcurrentHTTPRequests(t *testing.T) {
	const requestCount = 64

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "%s|%s", r.URL.Path, body)
	}))
	defer upstream.Close()

	upstreamAddr := upstream.Listener.Addr().String()
	upstreamHost, upstreamPort, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	upstreamIP := net.ParseIP(upstreamHost)
	if upstreamIP == nil {
		t.Fatalf("ParseIP(%q) = nil", upstreamHost)
	}

	tracker := NewTracker(60 * time.Second)
	tracker.Observe("upstream.test", upstreamIP, 30*time.Second, time.Unix(100, 0))
	summary := NewSummary()
	engine := NewPolicyEngine(PolicyConfig{}, tracker)

	var dialCount atomic.Int64
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCount.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}

	var wg sync.WaitGroup
	errCh := make(chan error, requestCount)
	for i := 0; i < requestCount; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			clientSide, proxySide := net.Pipe()
			defer clientSide.Close()

			handleErr := make(chan error, 1)
			go func() {
				handleErr <- proxy.handleConn(context.Background(), proxySide)
			}()

			payload := fmt.Sprintf("payload-%03d", i)
			targetURL := fmt.Sprintf("http://%s/req-%03d", upstreamAddr, i)
			req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", targetURL, upstreamAddr, len(payload), payload)
			if err := writeDestinationHeader(clientSide, net.JoinHostPort(upstreamHost, upstreamPort)); err != nil {
				errCh <- fmt.Errorf("writeDestinationHeader(%d): %w", i, err)
				return
			}
			if _, err := io.WriteString(clientSide, req); err != nil {
				errCh <- fmt.Errorf("WriteString(%d): %w", i, err)
				return
			}

			resp, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
			if err != nil {
				errCh <- fmt.Errorf("ReadResponse(%d): %w", i, err)
				return
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				errCh <- fmt.Errorf("ReadAll body(%d): %w", i, err)
				return
			}
			wantBody := fmt.Sprintf("/req-%03d|%s", i, payload)
			if string(body) != wantBody {
				errCh <- fmt.Errorf("response body(%d) = %q, want %q", i, string(body), wantBody)
				return
			}
			_ = clientSide.Close()
			if err := <-handleErr; err != nil {
				errCh <- fmt.Errorf("handleConn(%d): %w", i, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	if got, want := dialCount.Load(), int64(requestCount); got != want {
		t.Fatalf("dialCount = %d, want %d", got, want)
	}
	assertSummaryReportContains(t, summary, "tcp  upstream.test:"+upstreamPort+" policy=allowed count=64")
}

func TestTCPProxyHandlesConcurrentRawStreams(t *testing.T) {
	const streamCount = 64

	upstreamListener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer upstreamListener.Close()

	go func() {
		for {
			conn, err := upstreamListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if _, err := io.Copy(conn, conn); err != nil && err != io.EOF && !strings.Contains(err.Error(), "closed") {
					t.Errorf("echo server copy error = %v", err)
				}
			}(conn)
		}
	}()

	upstreamHost, upstreamPort, err := net.SplitHostPort(upstreamListener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	upstreamIP := net.ParseIP(upstreamHost)
	if upstreamIP == nil {
		t.Fatalf("ParseIP(%q) = nil", upstreamHost)
	}

	tracker := NewTracker(60 * time.Second)
	tracker.Observe("tunnel.test", upstreamIP, 30*time.Second, time.Unix(100, 0))
	summary := NewSummary()
	engine := NewPolicyEngine(PolicyConfig{}, tracker)

	var dialCount atomic.Int64
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCount.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}

	var wg sync.WaitGroup
	errCh := make(chan error, streamCount)
	for i := 0; i < streamCount; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			clientSide, proxySide := net.Pipe()
			defer clientSide.Close()

			handleErr := make(chan error, 1)
			go func() {
				handleErr <- proxy.handleConn(context.Background(), proxySide)
			}()

			if err := writeDestinationHeader(clientSide, net.JoinHostPort(upstreamHost, upstreamPort)); err != nil {
				errCh <- fmt.Errorf("writeDestinationHeader(%d): %w", i, err)
				return
			}

			payload := strings.Repeat(fmt.Sprintf("chunk-%03d-", i), 128)
			if _, err := io.WriteString(clientSide, payload); err != nil {
				errCh <- fmt.Errorf("stream write(%d): %w", i, err)
				return
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(clientSide, reply); err != nil {
				errCh <- fmt.Errorf("stream read(%d): %w", i, err)
				return
			}
			if string(reply) != payload {
				errCh <- fmt.Errorf("stream payload(%d) mismatch", i)
				return
			}
			_ = clientSide.Close()
			if err := <-handleErr; err != nil {
				errCh <- fmt.Errorf("handleConn(%d): %w", i, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	if got, want := dialCount.Load(), int64(streamCount); got != want {
		t.Fatalf("dialCount = %d, want %d", got, want)
	}
	assertSummaryReportContains(t, summary, "tcp  tunnel.test:"+upstreamPort+" policy=allowed count=64")
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
		_ = tls.Client(clientConn, cfg).HandshakeContext(context.Background())
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
