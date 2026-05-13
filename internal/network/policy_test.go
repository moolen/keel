package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPolicyAuthorizesEndpointByHostPortAndSNI(t *testing.T) {
	policy := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:            "api.github.com",
			Port:            443,
			RequireSNIMatch: true,
			HTTP: HTTPPolicyConfig{
				Default: "allow",
			},
		}},
	}, NewTracker(60*time.Second))

	dnsDecision, authorizations := policy.EvaluateDNS("api.github.com")
	if !dnsDecision.Allowed || len(authorizations) != 1 {
		t.Fatalf("EvaluateDNS() = %+v, authorizations=%+v", dnsDecision, authorizations)
	}
	policy.ObserveDNS("api.github.com", []net.IP{net.ParseIP("140.82.112.6")}, 30*time.Second, time.Unix(100, 0), authorizations)

	decision := policy.EvaluateTCP(net.ParseIP("140.82.112.6"), 443, "api.github.com", true, time.Unix(110, 0))
	if !decision.Allowed {
		t.Fatalf("EvaluateTCP() denied: %+v", decision)
	}
	if decision.EndpointHost != "api.github.com" || decision.Rule != "endpoint:api.github.com:443" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.HTTP.ScopeHost != "api.github.com" {
		t.Fatalf("decision.HTTP.ScopeHost = %q, want api.github.com", decision.HTTP.ScopeHost)
	}
}

func TestPolicyDoesNotReuseEndpointAuthorizationAcrossPortsOrSiblingHosts(t *testing.T) {
	policy := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:            "api.github.com",
			Port:            443,
			RequireSNIMatch: true,
		}},
	}, NewTracker(60*time.Second))
	dnsDecision, authorizations := policy.EvaluateDNS("api.github.com")
	if !dnsDecision.Allowed {
		t.Fatalf("EvaluateDNS() denied: %+v", dnsDecision)
	}
	policy.ObserveDNS("api.github.com", []net.IP{net.ParseIP("140.82.112.6")}, 30*time.Second, time.Unix(100, 0), authorizations)

	if decision := policy.EvaluateTCP(net.ParseIP("140.82.112.6"), 80, "", false, time.Unix(110, 0)); decision.Allowed {
		t.Fatalf("port 80 decision allowed: %+v", decision)
	}
	if decision := policy.EvaluateTCP(net.ParseIP("140.82.112.6"), 443, "gist.github.com", true, time.Unix(110, 0)); decision.Allowed {
		t.Fatalf("sibling host decision allowed: %+v", decision)
	}
}

func TestPolicyAllowsDirectIPOnlyByCIDRAndPort(t *testing.T) {
	policy := NewPolicyEngine(PolicyConfig{
		IPRules: []IPRule{{CIDR: "10.20.0.0/16", Port: 5432}},
	}, NewTracker(60*time.Second))

	allowed := policy.EvaluateTCP(net.ParseIP("10.20.1.5"), 5432, "", false, time.Unix(110, 0))
	if !allowed.Allowed || allowed.Rule != "ip:10.20.0.0/16:5432" {
		t.Fatalf("direct IP decision = %+v", allowed)
	}
	if denied := policy.EvaluateTCP(net.ParseIP("10.20.1.5"), 443, "", false, time.Unix(110, 0)); denied.Allowed {
		t.Fatalf("wrong port allowed: %+v", denied)
	}
}

func TestPolicyAuditConvertsDeniedDNSAndTCPDecisions(t *testing.T) {
	policy := NewPolicyEngine(PolicyConfig{Audit: true}, NewTracker(60*time.Second))

	dnsDecision, authorizations := policy.EvaluateDNS("gist.github.com")
	if !dnsDecision.Allowed || !dnsDecision.WouldDeny || len(authorizations) != 0 {
		t.Fatalf("EvaluateDNS() = %+v, authorizations=%+v, want allowed+would_deny without auths", dnsDecision, authorizations)
	}
	if dnsDecision.Reason != "host not covered by endpoint" {
		t.Fatalf("dnsDecision.Reason = %q, want host not covered by endpoint", dnsDecision.Reason)
	}

	tcpDecision := policy.EvaluateTCP(net.ParseIP("140.82.112.6"), 443, "", true, time.Unix(110, 0))
	if !tcpDecision.Allowed || !tcpDecision.WouldDeny {
		t.Fatalf("EvaluateTCP() = %+v, want allowed+would_deny", tcpDecision)
	}
}

func TestSummaryLabelsWouldDeny(t *testing.T) {
	summary := NewSummary()
	decision := Decision{
		Allowed:   true,
		WouldDeny: true,
		Reason:    "dns denied",
		Rule:      "*.github.com",
	}

	summary.RecordDNS("api.github.com", decision)
	summary.RecordHTTP("api.github.com", "GET", "/repos/123", decision)

	assertPolicySummaryReportContains(t, summary, "dns  api.github.com:53 policy=would_deny count=1")
	assertPolicySummaryReportContains(t, summary, "http api.github.com GET /repos/123 policy=would_deny count=1")
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

func assertPolicySummaryReportContains(t *testing.T, summary *Summary, want string) {
	t.Helper()

	var buf bytes.Buffer
	if err := summary.WriteReport(&buf); err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("summary report =\n%s\nwant line containing %q", buf.String(), want)
	}
}
