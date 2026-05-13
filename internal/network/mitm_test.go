package network

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMITMProxyAllowsHTTPRequest(t *testing.T) {
	proxyCA, err := LoadOrCreateCA(CAOptions{Dir: t.TempDir(), Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	upstreamRootPEM, upstreamTLS := mustUpstreamTLSServer(t, "api.github.com", func(req *http.Request) *http.Response {
		if req.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", req.Method)
		}
		if req.Host != "api.github.com" {
			t.Fatalf("host = %s, want api.github.com", req.Host)
		}
		if req.URL.Path != "/repos/123" {
			t.Fatalf("path = %s, want /repos/123", req.URL.Path)
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: int64(len("ok")),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("ok")),
			Close:         true,
		}
	})
	defer upstreamTLS.Close()

	roots, err := CertPoolFromPEM(upstreamRootPEM)
	if err != nil {
		t.Fatal(err)
	}
	mitmRoots, err := CertPoolFromPEM(proxyCA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	summary := NewSummary()
	proxy := &MITMProxy{
		Enabled: true,
		CA:      proxyCA,
		Policy:  NewHTTPPolicy(HTTPPolicyConfig{Default: "deny", Rules: []HTTPRule{{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/repos/*"}}}}),
		Summary: summary,
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, upstreamTLS.Addr().String())
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.HandleTLS(context.Background(), proxySide, "api.github.com", upstreamTLS.Addr().String())
	}()

	clientTLS := tls.Client(clientSide, &tls.Config{
		RootCAs:    mitmRoots,
		ServerName: "api.github.com",
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error = %v", err)
	}

	if _, err := io.WriteString(clientTLS, "GET /repos/123 HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", string(body))
	}

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("HandleTLS() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HandleTLS")
	}

	assertSummaryReportContains(t, summary, "http api.github.com GET /repos/123 policy=allowed count=1")
}

func TestMITMProxyRejectsHTTPRequestOutsideEndpointScope(t *testing.T) {
	proxyCA, err := LoadOrCreateCA(CAOptions{Dir: t.TempDir(), Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}
	mitmRoots, err := CertPoolFromPEM(proxyCA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	summary := NewSummary()
	var dialed atomic.Bool
	proxy := &MITMProxy{
		Enabled: true,
		CA:      proxyCA,
		Policy: NewHTTPPolicy(HTTPPolicyConfig{
			ScopeHost: "api.github.com",
			Default:   "allow",
		}),
		Summary: summary,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, io.ErrClosedPipe
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.HandleTLS(context.Background(), proxySide, "api.github.com", "203.0.113.10:443")
	}()

	clientTLS := tls.Client(clientSide, &tls.Config{
		RootCAs:    mitmRoots,
		ServerName: "api.github.com",
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error = %v", err)
	}
	if _, err := io.WriteString(clientTLS, "GET / HTTP/1.1\r\nHost: gist.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if dialed.Load() {
		t.Fatal("dialer was called for request outside endpoint scope")
	}
	_ = clientTLS.Close()

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("HandleTLS() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HandleTLS")
	}

	assertSummaryReportContains(t, summary, "http gist.github.com GET / policy=denied count=1")
}

func TestMITMProxyKeepsConnectionAliveAcrossRequests(t *testing.T) {
	proxyCA, err := LoadOrCreateCA(CAOptions{Dir: t.TempDir(), Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	var requestCount atomic.Int32
	upstreamRootPEM, upstreamTLS := mustUpstreamTLSServer(t, "api.github.com", func(req *http.Request) *http.Response {
		count := requestCount.Add(1)
		body := "first"
		if count == 2 {
			body = "second"
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: int64(len(body)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(body)),
		}
	})
	defer upstreamTLS.Close()

	roots, err := CertPoolFromPEM(upstreamRootPEM)
	if err != nil {
		t.Fatal(err)
	}
	mitmRoots, err := CertPoolFromPEM(proxyCA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	summary := NewSummary()
	proxy := &MITMProxy{
		Enabled: true,
		CA:      proxyCA,
		Policy:  NewHTTPPolicy(HTTPPolicyConfig{Default: "deny", Rules: []HTTPRule{{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/*"}}}}),
		Summary: summary,
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, upstreamTLS.Addr().String())
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.HandleTLS(context.Background(), proxySide, "api.github.com", upstreamTLS.Addr().String())
	}()

	clientTLS := tls.Client(clientSide, &tls.Config{
		RootCAs:    mitmRoots,
		ServerName: "api.github.com",
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error = %v", err)
	}

	reader := bufio.NewReader(clientTLS)
	for i, want := range []string{"first", "second"} {
		path := "/repos/one"
		if i == 1 {
			path = "/repos/two"
		}
		if _, err := io.WriteString(clientTLS, "GET "+path+" HTTP/1.1\r\nHost: api.github.com\r\n\r\n"); err != nil {
			t.Fatalf("client write error = %v", err)
		}
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("ReadResponse() error = %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if string(body) != want {
			t.Fatalf("body = %q, want %q", string(body), want)
		}
	}

	_ = clientTLS.Close()

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("HandleTLS() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HandleTLS")
	}

	assertSummaryReportContains(t, summary, "http api.github.com GET /repos/one policy=allowed count=1")
	assertSummaryReportContains(t, summary, "http api.github.com GET /repos/two policy=allowed count=1")
}

func TestMITMProxyDeniesHTTPRequest(t *testing.T) {
	proxyCA, err := LoadOrCreateCA(CAOptions{Dir: t.TempDir(), Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}
	mitmRoots, err := CertPoolFromPEM(proxyCA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	var dialed atomic.Bool
	summary := NewSummary()
	proxy := &MITMProxy{
		Enabled: true,
		CA:      proxyCA,
		Policy:  nil,
		Summary: summary,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, io.EOF
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.HandleTLS(context.Background(), proxySide, "api.github.com", "203.0.113.10:443")
	}()

	clientTLS := tls.Client(clientSide, &tls.Config{
		RootCAs:    mitmRoots,
		ServerName: "api.github.com",
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error = %v", err)
	}

	if _, err := io.WriteString(clientTLS, "GET /private HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(string(body), "blocked by keel policy") {
		t.Fatalf("body = %q, want deny message", string(body))
	}
	if dialed.Load() {
		t.Fatal("unexpected upstream dial for denied request")
	}

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("HandleTLS() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HandleTLS")
	}

	assertSummaryReportContains(t, summary, "http api.github.com GET /private policy=denied count=1")
}

func TestMITMProxyAllowsDeniedHTTPRequestInAuditMode(t *testing.T) {
	proxyCA, err := LoadOrCreateCA(CAOptions{Dir: t.TempDir(), Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	upstreamRootPEM, upstreamTLS := mustUpstreamTLSServer(t, "api.github.com", func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: int64(len("audited")),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("audited")),
			Close:         true,
		}
	})
	defer upstreamTLS.Close()

	roots, err := CertPoolFromPEM(upstreamRootPEM)
	if err != nil {
		t.Fatal(err)
	}
	mitmRoots, err := CertPoolFromPEM(proxyCA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	summary := NewSummary()
	proxy := &MITMProxy{
		Enabled: true,
		CA:      proxyCA,
		Policy:  NewHTTPPolicy(HTTPPolicyConfig{Default: "deny", Audit: true}),
		Summary: summary,
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, upstreamTLS.Addr().String())
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.HandleTLS(context.Background(), proxySide, "api.github.com", upstreamTLS.Addr().String())
	}()

	clientTLS := tls.Client(clientSide, &tls.Config{
		RootCAs:    mitmRoots,
		ServerName: "api.github.com",
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error = %v", err)
	}

	if _, err := io.WriteString(clientTLS, "GET /private HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "audited" {
		t.Fatalf("body = %q, want audited", string(body))
	}

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("HandleTLS() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HandleTLS")
	}

	assertSummaryReportContains(t, summary, "http api.github.com GET /private policy=would_deny count=1")
}

func TestMITMProxyDeniesWithoutSummaryCollector(t *testing.T) {
	proxyCA, err := LoadOrCreateCA(CAOptions{Dir: t.TempDir(), Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}
	mitmRoots, err := CertPoolFromPEM(proxyCA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	var dialed atomic.Bool
	proxy := &MITMProxy{
		Enabled: true,
		CA:      proxyCA,
		Policy:  nil,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, io.EOF
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.HandleTLS(context.Background(), proxySide, "api.github.com", "203.0.113.10:443")
	}()

	clientTLS := tls.Client(clientSide, &tls.Config{
		RootCAs:    mitmRoots,
		ServerName: "api.github.com",
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error = %v", err)
	}

	if _, err := io.WriteString(clientTLS, "GET /private HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if dialed.Load() {
		t.Fatal("unexpected upstream dial for denied request")
	}
	_ = clientTLS.Close()

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("HandleTLS() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HandleTLS")
	}
}

func TestMITMProxyReturnsBadGatewayOnUpstreamFailure(t *testing.T) {
	proxyCA, err := LoadOrCreateCA(CAOptions{Dir: t.TempDir(), Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}
	mitmRoots, err := CertPoolFromPEM(proxyCA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	summary := NewSummary()
	proxy := &MITMProxy{
		Enabled: true,
		CA:      proxyCA,
		Policy:  NewHTTPPolicy(HTTPPolicyConfig{Default: "allow"}),
		Summary: summary,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, io.EOF
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.HandleTLS(context.Background(), proxySide, "api.github.com", "203.0.113.10:443")
	}()

	clientTLS := tls.Client(clientSide, &tls.Config{
		RootCAs:    mitmRoots,
		ServerName: "api.github.com",
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error = %v", err)
	}
	if _, err := io.WriteString(clientTLS, "GET /repos/123 HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if !strings.Contains(string(body), "upstream request failed") {
		t.Fatalf("body = %q, want upstream failure message", string(body))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("HandleTLS() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HandleTLS")
	}
}

func TestTCPProxyUsesMITMForEligibleTLSFlows(t *testing.T) {
	proxyCA, err := LoadOrCreateCA(CAOptions{Dir: t.TempDir(), Name: "keel-local-ca"})
	if err != nil {
		t.Fatal(err)
	}

	upstreamRootPEM, upstreamTLS := mustUpstreamTLSServer(t, "api.github.com", func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: int64(len("mitm")),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("mitm")),
			Close:         true,
		}
	})
	defer upstreamTLS.Close()

	roots, err := CertPoolFromPEM(upstreamRootPEM)
	if err != nil {
		t.Fatal(err)
	}
	mitmRoots, err := CertPoolFromPEM(proxyCA.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	tracker := NewTracker(60 * time.Second)
	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:            "api.github.com",
			Port:            443,
			RequireSNIMatch: true,
			MITMRequired:    true,
			HTTP: HTTPPolicyConfig{
				Default: "deny",
				Rules:   []HTTPRule{{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/*"}}},
			},
		}},
	}, tracker)
	observeEndpointDNS(t, engine, "api.github.com", "203.0.113.10")

	summary := NewSummary()
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("raw tunnel dial should not be used when MITM is active")
			return nil, io.EOF
		},
		MITM: &MITMProxy{
			Enabled: true,
			CA:      proxyCA,
			Policy:  NewHTTPPolicy(HTTPPolicyConfig{Default: "deny"}),
			Summary: summary,
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, upstreamTLS.Addr().String())
			},
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:443"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}

	clientTLS := tls.Client(clientSide, &tls.Config{
		RootCAs:    mitmRoots,
		ServerName: "api.github.com",
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error = %v", err)
	}
	if _, err := io.WriteString(clientTLS, "GET / HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "mitm" {
		t.Fatalf("unexpected response status=%d body=%q", resp.StatusCode, string(body))
	}

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}

	assertSummaryReportContains(t, summary, "tcp  api.github.com:443 policy=allowed count=1")
	assertSummaryReportContains(t, summary, "http api.github.com GET / policy=allowed count=1")
}

func TestDNSProxyAllowsDeniedDomainInAuditMode(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	summary := NewSummary()
	engine := NewPolicyEngine(PolicyConfig{
		Audit:     true,
		Endpoints: []EndpointRule{{Host: "api.github.com", Port: 443}},
	}, tracker)
	resolver := &stubResolver{
		response: mustDNSResponse(t, "gist.github.com.", "140.82.112.7", 30),
	}
	proxy := DNSProxy{
		Policy:   engine,
		Resolver: resolver,
		Summary:  summary,
		Now:      func() time.Time { return time.Unix(100, 0) },
	}

	reply, err := proxy.HandleQuery(context.Background(), mustDNSQuery(t, "gist.github.com."))
	if err != nil {
		t.Fatalf("HandleQuery() error = %v", err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want success", reply.Rcode)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}

	assertSummaryReportContains(t, summary, "dns  gist.github.com:53 policy=would_deny count=1")
}

func TestTCPProxyAllowsDeniedDestinationInAuditMode(t *testing.T) {
	engine := NewPolicyEngine(PolicyConfig{Audit: true}, NewTracker(60*time.Second))
	summary := NewSummary()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	upstreamProxy, upstreamServer := net.Pipe()
	defer upstreamServer.Close()

	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
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

	if err := writeDestinationHeader(clientSide, "198.51.100.25:80"); err != nil {
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
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}

	assertSummaryReportContains(t, summary, "tcp  198.51.100.25:80 policy=would_deny count=1")
}

func TestTCPProxyUsesMITMForPlainHTTPFlows(t *testing.T) {
	upstreamHTTP := mustUpstreamHTTPServer(t, func(req *http.Request) *http.Response {
		if req.Host != "api.github.com" {
			t.Fatalf("host = %s, want api.github.com", req.Host)
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: int64(len("plain")),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("plain")),
			Close:         true,
		}
	})
	defer upstreamHTTP.Close()

	tracker := NewTracker(60 * time.Second)
	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:         "api.github.com",
			Port:         80,
			MITMRequired: true,
			HTTP: HTTPPolicyConfig{
				Default: "deny",
				Rules:   []HTTPRule{{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/*"}}},
			},
		}},
	}, tracker)
	observeEndpointDNS(t, engine, "api.github.com", "203.0.113.10")

	summary := NewSummary()
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		MITM: &MITMProxy{
			Enabled: true,
			Policy:  NewHTTPPolicy(HTTPPolicyConfig{Default: "deny"}),
			Summary: summary,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, upstreamHTTP.Addr().String())
			},
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:80"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := io.WriteString(clientSide, "GET / HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "plain" {
		t.Fatalf("unexpected response status=%d body=%q", resp.StatusCode, string(body))
	}

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}

	assertSummaryReportContains(t, summary, "tcp  api.github.com:80 policy=allowed count=1")
	assertSummaryReportContains(t, summary, "http api.github.com GET / policy=allowed count=1")
}

func TestTCPProxyRejectsPlainHTTPOutsideEndpointScope(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:         "api.github.com",
			Port:         80,
			MITMRequired: true,
			HTTP: HTTPPolicyConfig{
				Default: "allow",
			},
		}},
	}, tracker)
	observeEndpointDNS(t, engine, "api.github.com", "203.0.113.10")

	summary := NewSummary()
	var dialed atomic.Bool
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		MITM: &MITMProxy{
			Enabled: true,
			Policy:  NewHTTPPolicy(HTTPPolicyConfig{Default: "allow"}),
			Summary: summary,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				dialed.Store(true)
				return nil, io.ErrClosedPipe
			},
		},
	}

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:80"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := io.WriteString(clientSide, "GET / HTTP/1.1\r\nHost: gist.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if dialed.Load() {
		t.Fatal("dialer was called for request outside endpoint scope")
	}
	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}

	assertSummaryReportContains(t, summary, "tcp  api.github.com:80 policy=allowed count=1")
	assertSummaryReportContains(t, summary, "http gist.github.com GET / policy=denied count=1")
}

func TestTCPProxyBypassesMITMForPlainHTTPBypassHost(t *testing.T) {
	tracker := NewTracker(60 * time.Second)

	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{Host: "api.github.com", Port: 80}},
	}, tracker)
	observeEndpointDNS(t, engine, "api.github.com", "203.0.113.10")
	summary := NewSummary()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	upstreamProxy, upstreamServer := net.Pipe()
	defer upstreamServer.Close()

	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return upstreamProxy, nil
		},
		MITM: &MITMProxy{
			Enabled:     true,
			BypassHosts: []string{"api.github.com"},
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	request := "GET / HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"
	upstreamPayload := make(chan []byte, 1)
	go func() {
		defer upstreamServer.Close()
		buf := make([]byte, len(request))
		n, err := io.ReadFull(upstreamServer, buf)
		if err != nil {
			t.Errorf("upstream read error = %v", err)
			return
		}
		upstreamPayload <- append([]byte(nil), buf[:n]...)
		_, _ = upstreamServer.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:80"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := io.WriteString(clientSide, request); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientSide), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	_ = resp.Body.Close()
	_ = clientSide.Close()

	select {
	case payload := <-upstreamPayload:
		if string(payload) != request {
			t.Fatalf("upstream payload = %q, want %q", string(payload), request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream payload")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
}

func TestTCPProxyFallsBackToRawTunnelWhenMITMDisabled(t *testing.T) {
	tracker := NewTracker(60 * time.Second)

	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{Host: "api.github.com", Port: 443}},
	}, tracker)
	observeEndpointDNS(t, engine, "api.github.com", "203.0.113.10")
	summary := NewSummary()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	upstreamProxy, upstreamServer := net.Pipe()
	defer upstreamServer.Close()

	preface := mustClientHelloBytesForTCP(t, "api.github.com")

	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return upstreamProxy, nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	upstreamPayload := make(chan []byte, 1)
	go func() {
		defer upstreamServer.Close()
		buf := make([]byte, len(preface)+4)
		n, err := io.ReadFull(upstreamServer, buf)
		if err != nil {
			t.Errorf("upstream read error = %v", err)
			return
		}
		upstreamPayload <- buf[:n]
		_, _ = upstreamServer.Write([]byte("pong"))
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:443"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := clientSide.Write(preface); err != nil {
		t.Fatalf("client write preface error = %v", err)
	}
	if _, err := clientSide.Write([]byte("ping")); err != nil {
		t.Fatalf("client write payload error = %v", err)
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
	case payload := <-upstreamPayload:
		if string(payload[:len(preface)]) != string(preface) {
			t.Fatal("client hello preface was not forwarded upstream")
		}
		if string(payload[len(preface):]) != "ping" {
			t.Fatalf("upstream payload = %q, want ping", string(payload[len(preface):]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream payload")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
}

func TestTCPProxyBypassesMITMForConfiguredSNI(t *testing.T) {
	tracker := NewTracker(60 * time.Second)

	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{Host: "api.github.com", Port: 443}},
	}, tracker)
	observeEndpointDNS(t, engine, "api.github.com", "203.0.113.10")
	summary := NewSummary()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	upstreamProxy, upstreamServer := net.Pipe()
	defer upstreamServer.Close()

	preface := mustClientHelloBytesForTCP(t, "api.github.com")

	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return upstreamProxy, nil
		},
		MITM: &MITMProxy{
			Enabled:   true,
			BypassSNI: []string{"api.github.com"},
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	upstreamPayload := make(chan []byte, 1)
	go func() {
		defer upstreamServer.Close()
		buf := make([]byte, len(preface)+4)
		n, err := io.ReadFull(upstreamServer, buf)
		if err != nil {
			t.Errorf("upstream read error = %v", err)
			return
		}
		upstreamPayload <- buf[:n]
		_, _ = upstreamServer.Write([]byte("pong"))
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:443"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := clientSide.Write(preface); err != nil {
		t.Fatalf("client write preface error = %v", err)
	}
	if _, err := clientSide.Write([]byte("ping")); err != nil {
		t.Fatalf("client write payload error = %v", err)
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
	case payload := <-upstreamPayload:
		if string(payload[:len(preface)]) != string(preface) {
			t.Fatal("client hello preface was not forwarded upstream")
		}
		if string(payload[len(preface):]) != "ping" {
			t.Fatalf("upstream payload = %q, want ping", string(payload[len(preface):]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream payload")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
}

func TestTCPProxyDeniesWhenMITMInspectionFails(t *testing.T) {
	tracker := NewTracker(60 * time.Second)

	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:         "api.github.com",
			Port:         443,
			MITMRequired: true,
		}},
	}, tracker)
	observeEndpointDNS(t, engine, "api.github.com", "203.0.113.10")
	summary := NewSummary()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	var dialed atomic.Bool
	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, io.EOF
		},
		MITM: &MITMProxy{
			Enabled: true,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:443"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := clientSide.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x00}); err != nil {
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

	if dialed.Load() {
		t.Fatal("unexpected dial for inspection failure")
	}
	assertSummaryReportContains(t, summary, "tcp  api.github.com:443 policy=denied count=1")
}

func TestTCPProxyAllowsIncompleteTLSClientHelloToTunnel(t *testing.T) {
	tracker := NewTracker(60 * time.Second)

	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{Host: "api.github.com", Port: 443}},
	}, tracker)
	observeEndpointDNS(t, engine, "api.github.com", "203.0.113.10")
	summary := NewSummary()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	upstreamProxy, upstreamServer := net.Pipe()
	defer upstreamServer.Close()

	firstRecord, secondRecord := splitClientHelloAcrossRecords(t, "api.github.com")

	proxy := TCPProxy{
		Policy:  engine,
		Summary: summary,
		Now: func() time.Time {
			return time.Unix(110, 0)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return upstreamProxy, nil
		},
		MITM: &MITMProxy{
			Enabled: true,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.handleConn(context.Background(), proxySide)
	}()

	upstreamPayload := make(chan []byte, 1)
	go func() {
		defer upstreamServer.Close()
		buf := make([]byte, len(firstRecord)+len(secondRecord))
		n, err := io.ReadFull(upstreamServer, buf)
		if err != nil {
			t.Errorf("upstream read error = %v", err)
			return
		}
		upstreamPayload <- append([]byte(nil), buf[:n]...)
		_, _ = upstreamServer.Write([]byte("pong"))
	}()

	if err := writeDestinationHeader(clientSide, "203.0.113.10:443"); err != nil {
		t.Fatalf("writeDestinationHeader() error = %v", err)
	}
	if _, err := clientSide.Write(firstRecord); err != nil {
		t.Fatalf("client write first record error = %v", err)
	}
	if _, err := clientSide.Write(secondRecord); err != nil {
		t.Fatalf("client write second record error = %v", err)
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
	case payload := <-upstreamPayload:
		want := append(append([]byte(nil), firstRecord...), secondRecord...)
		if string(payload) != string(want) {
			t.Fatal("fragmented client hello was not tunneled intact")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream payload")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleConn() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleConn")
	}
}

func mustUpstreamTLSServer(t *testing.T, host string, handler func(*http.Request) *http.Response) ([]byte, net.Listener) {
	t.Helper()

	rootCertPEM, rootKeyPEM, rootCert, rootKey := mustCertificateAuthority(t, "test-upstream-root")
	_ = rootKeyPEM
	leafPEM, leafKeyPEM := mustLeafCertificate(t, rootCert, rootKey, host)
	cert, err := tls.X509KeyPair(leafPEM, leafKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					req, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					resp := handler(req)
					if resp.Header == nil {
						resp.Header = make(http.Header)
					}
					if err := resp.Write(conn); err != nil {
						closeRequestBody(req)
						_ = resp.Body.Close()
						return
					}
					closeRequestBody(req)
					_ = resp.Body.Close()
					if req.Close || resp.Close {
						return
					}
				}
			}(conn)
		}
	}()

	return rootCertPEM, listener
}

func mustUpstreamHTTPServer(t *testing.T, handler func(*http.Request) *http.Response) net.Listener {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					req, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					resp := handler(req)
					if resp.Header == nil {
						resp.Header = make(http.Header)
					}
					if err := resp.Write(conn); err != nil {
						closeRequestBody(req)
						_ = resp.Body.Close()
						return
					}
					closeRequestBody(req)
					_ = resp.Body.Close()
					if req.Close || resp.Close {
						return
					}
				}
			}(conn)
		}
	}()

	return listener
}

func mustCertificateAuthority(t *testing.T, name string) ([]byte, []byte, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		cert,
		key
}

func mustLeafCertificate(t *testing.T, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, host string) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func splitClientHelloAcrossRecords(t *testing.T, serverName string) ([]byte, []byte) {
	t.Helper()

	full := mustClientHelloBytesForTCP(t, serverName)
	if len(full) < 16 {
		t.Fatalf("client hello too short: %d", len(full))
	}

	body := full[5:]
	split := len(body) / 2
	if split < 8 {
		split = 8
	}
	first := append([]byte{0x16, full[1], full[2], byte(split >> 8), byte(split)}, body[:split]...)
	remaining := body[split:]
	secondLen := len(remaining)
	second := append([]byte{0x16, full[1], full[2], byte(secondLen >> 8), byte(secondLen)}, remaining...)
	return first, second
}
