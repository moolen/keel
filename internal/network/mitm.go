package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type MITMProxy struct {
	Enabled         bool
	BypassHosts     []string
	BypassSNI       []string
	CA              *CA
	Policy          *HTTPPolicy
	Summary         *Summary
	DialContext     func(context.Context, string, string) (net.Conn, error)
	TLSClientConfig *tls.Config
}

func (p *MITMProxy) EnabledFor(serverName string) bool {
	if p == nil || !p.Enabled {
		return false
	}

	name := normalizeHTTPHost(serverName)
	if matchesAnyHostPattern(name, p.BypassSNI) || matchesAnyHostPattern(name, p.BypassHosts) {
		return false
	}
	return true
}

func (p *MITMProxy) HandleHTTP(ctx context.Context, downstream net.Conn, upstreamAddr string) error {
	return p.handleHTTPStream(ctx, downstream, upstreamAddr, false, "")
}

func (p *MITMProxy) HandleTLS(ctx context.Context, downstream net.Conn, serverName, upstreamAddr string) error {
	if p == nil {
		return fmt.Errorf("mitm proxy not configured")
	}
	if p.CA == nil {
		return fmt.Errorf("mitm ca not configured")
	}

	leaf, err := p.CA.IssueLeaf(serverName)
	if err != nil {
		return err
	}
	certificate, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		return err
	}

	terminated := tls.Server(downstream, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		ServerName:   serverName,
	})

	if err := terminated.HandshakeContext(ctx); err != nil {
		return err
	}

	return p.handleHTTPStream(ctx, terminated, upstreamAddr, true, serverName)
}

func (p *MITMProxy) handleHTTPStream(ctx context.Context, downstream net.Conn, upstreamAddr string, upstreamTLS bool, serverName string) error {
	reader := bufio.NewReader(downstream)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF || err == net.ErrClosed {
				return nil
			}
			return err
		}

		host := req.Host
		if host == "" {
			host = serverName
		}
		bypassed := matchesAnyHostPattern(host, p.BypassHosts)

		if !bypassed {
			decision := p.evaluateHTTPRequest(req, host)
			if p.Summary != nil {
				p.Summary.RecordHTTP(host, req.Method, requestPath(req), decision)
			}
			if !decision.Allowed {
				closeRequestBody(req)
				return writeDeniedHTTPResponse(downstream)
			}
		}

		shouldClose, err := p.forwardRequest(ctx, downstream, req, upstreamAddr, upstreamTLS, serverName, host)
		if err != nil {
			closeRequestBody(req)
			return err
		}
		if shouldClose {
			return nil
		}
	}
}

func (p *MITMProxy) forwardRequest(ctx context.Context, downstream net.Conn, req *http.Request, upstreamAddr string, upstreamTLS bool, serverName, host string) (bool, error) {
	resp, upstreamConn, err := p.roundTrip(ctx, req, upstreamAddr, upstreamTLS, serverName, host)
	if err != nil {
		closeRequestBody(req)
		return true, writeHTTPErrorResponse(downstream, http.StatusBadGateway, "upstream request failed\n")
	}
	if err := resp.Write(downstream); err != nil {
		closeHTTPExchange(resp, upstreamConn)
		closeRequestBody(req)
		return true, err
	}
	shouldClose := req.Close || resp.Close
	closeHTTPExchange(resp, upstreamConn)
	closeRequestBody(req)
	return shouldClose, nil
}

func (p *MITMProxy) evaluateHTTPRequest(req *http.Request, host string) Decision {
	if p == nil || p.Policy == nil {
		return Decision{Allowed: false, Reason: "http policy not configured", Rule: "default"}
	}
	return p.Policy.Evaluate(HTTPRequest{
		Host:   host,
		Method: req.Method,
		Path:   requestPath(req),
	})
}

func (p *MITMProxy) roundTrip(ctx context.Context, req *http.Request, upstreamAddr string, upstreamTLS bool, serverName, host string) (*http.Response, net.Conn, error) {
	dialContext := p.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}

	upstream, err := dialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		return nil, nil, err
	}

	upstreamConn := upstream
	if upstreamTLS {
		tlsConfig := cloneTLSConfig(p.TLSClientConfig)
		name := normalizeHTTPHost(serverName)
		if name == "" {
			name = normalizeHTTPHost(host)
		}
		if name != "" {
			tlsConfig.ServerName = name
		}
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
		if len(tlsConfig.NextProtos) == 0 {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}

		tlsUpstream := tls.Client(upstream, tlsConfig)
		if err := tlsUpstream.HandshakeContext(ctx); err != nil {
			_ = upstream.Close()
			return nil, nil, err
		}
		upstreamConn = tlsUpstream
	}

	outReq := cloneHTTPRequest(ctx, req, host)
	if !upstreamTLS {
		outReq.URL.Scheme = "http"
	}
	if err := outReq.Write(upstreamConn); err != nil {
		_ = upstreamConn.Close()
		return nil, nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstreamConn), outReq)
	if err != nil {
		_ = upstreamConn.Close()
		return nil, nil, err
	}

	return resp, upstreamConn, nil
}

func requestPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return "/"
	}
	if path := req.URL.Path; path != "" {
		return path
	}
	return req.URL.RequestURI()
}

func cloneHTTPRequest(ctx context.Context, req *http.Request, host string) *http.Request {
	outReq := new(http.Request)
	*outReq = *req
	outReq = outReq.WithContext(ctx)
	outReq.RequestURI = ""
	if req.URL != nil {
		cloned := *req.URL
		outReq.URL = &cloned
	} else {
		outReq.URL = &url.URL{}
	}
	outReq.URL.Scheme = "https"
	if outReq.URL.Host == "" {
		outReq.URL.Host = normalizeHTTPHost(host)
	}
	outReq.Host = host
	return outReq
}

func writeDeniedHTTPResponse(w io.Writer) error {
	body := "blocked by keel policy\n"
	resp := &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        "403 Forbidden",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		Close:         true,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Connection", "close")
	return resp.Write(w)
}

func writeHTTPErrorResponse(w io.Writer, status int, body string) error {
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		Close:         true,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Connection", "close")
	return resp.Write(w)
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func closeRequestBody(req *http.Request) {
	if req != nil && req.Body != nil {
		_ = req.Body.Close()
	}
}

func closeHTTPExchange(resp *http.Response, conn net.Conn) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
}

func CertPoolFromPEM(certPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("append cert pem")
	}
	return pool, nil
}

func matchesAnyHostPattern(host string, patterns []string) bool {
	host = normalizeHTTPHost(host)
	for _, pattern := range patterns {
		pattern = normalizeHTTPHost(pattern)
		if pattern == "" {
			continue
		}
		ok, err := path.Match(pattern, host)
		if err == nil && ok {
			return true
		}
	}
	return false
}
