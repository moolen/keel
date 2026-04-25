package network

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestPolicyAllowsDNSAndCorrelatedTLS(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	engine := NewPolicyEngine(PolicyConfig{
		DNS: RuleSet{
			Allowed: []string{"*.github.com"},
			Denied:  []string{"gist.github.com"},
		},
		TCP: CIDRRuleSet{
			Denied: []string{"10.0.0.0/8"},
		},
		TLS: RuleSet{
			Allowed: []string{"github.com", "*.github.com"},
		},
		DenyIfNoSNI: true,
	}, tracker)

	if decision := engine.EvaluateDNS("api.github.com"); !decision.Allowed {
		t.Fatalf("EvaluateDNS(api.github.com) denied: %+v", decision)
	}
	if decision := engine.EvaluateDNS("gist.github.com"); decision.Allowed {
		t.Fatalf("EvaluateDNS(gist.github.com) allowed unexpectedly: %+v", decision)
	}

	tracker.Observe("api.github.com", net.ParseIP("140.82.112.6"), 30*time.Second, time.Unix(100, 0))
	decision := engine.EvaluateTCP(net.ParseIP("140.82.112.6"), 443, "api.github.com", time.Unix(110, 0))
	if !decision.Allowed {
		t.Fatalf("EvaluateTCP() denied: %+v", decision)
	}
	if decision.Rule != "dns:api.github.com" {
		t.Fatalf("decision.Rule = %q, want dns:api.github.com", decision.Rule)
	}

	decision = engine.EvaluateTCP(net.ParseIP("140.82.112.6"), 443, "", time.Unix(110, 0))
	if decision.Allowed {
		t.Fatalf("expected deny without SNI: %+v", decision)
	}
}

func TestParseClientHelloSNI(t *testing.T) {
	hello := mustClientHelloBytes(t, "api.github.com")

	serverName, err := ParseClientHelloSNI(hello)
	if err != nil {
		t.Fatalf("ParseClientHelloSNI() error = %v", err)
	}
	if serverName != "api.github.com" {
		t.Fatalf("serverName = %q, want api.github.com", serverName)
	}
}

func mustClientHelloBytes(t *testing.T, serverName string) []byte {
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
