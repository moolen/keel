package network

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type stubResolver struct {
	response *dns.Msg
	err      error
	calls    int
	lastName string
}

func (r *stubResolver) Exchange(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	r.calls++
	if len(msg.Question) > 0 {
		r.lastName = msg.Question[0].Name
	}
	if r.err != nil {
		return nil, r.err
	}
	return r.response.Copy(), nil
}

func TestDNSProxyAllowsAndTracksAnswers(t *testing.T) {
	tracker := NewTracker(0)
	summary := NewSummary()
	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{
			Host:            "*.github.com",
			Port:            443,
			RequireSNIMatch: true,
		}},
	}, tracker)
	resolver := &stubResolver{
		response: mustDNSResponse(t, "api.github.com.", "140.82.112.6", 30),
	}
	resolver.response.Answer = append(resolver.response.Answer, &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   "api.github.com.",
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    90,
		},
		AAAA: net.ParseIP("2606:50c0:8000::153"),
	})
	proxy := DNSProxy{
		Policy:   engine,
		Tracker:  tracker,
		Resolver: resolver,
		Summary:  summary,
		Now: func() time.Time {
			return time.Unix(100, 0)
		},
	}

	reply, err := proxy.HandleQuery(context.Background(), mustDNSQuery(t, "api.github.com."))
	if err != nil {
		t.Fatalf("HandleQuery() error = %v", err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want success", reply.Rcode)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}

	authorizations := tracker.Authorizations(net.ParseIP("140.82.112.6"), 443, time.Unix(110, 0))
	if len(authorizations) != 1 {
		t.Fatalf("tracked authorizations = %#v, want one", authorizations)
	}
	if authorizations[0].Host != "api.github.com" || authorizations[0].Port != 443 {
		t.Fatalf("tracked authorization = %+v, want api.github.com:443", authorizations[0])
	}
	if authorizations := tracker.Authorizations(net.ParseIP("140.82.112.6"), 443, time.Unix(131, 0)); len(authorizations) != 0 {
		t.Fatalf("expired A authorizations = %#v, want none", authorizations)
	}
	if authorizations := tracker.Authorizations(net.ParseIP("2606:50c0:8000::153"), 443, time.Unix(131, 0)); len(authorizations) != 1 {
		t.Fatalf("AAAA authorizations after A expiry = %#v, want one", authorizations)
	}

	assertSummaryReportContains(t, summary, "dns  api.github.com:53 policy=allowed count=1")
}

func TestDNSProxyDeniesEndpointMiss(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	summary := NewSummary()
	engine := NewPolicyEngine(PolicyConfig{
		Endpoints: []EndpointRule{{Host: "api.github.com", Port: 443}},
	}, tracker)
	resolver := &stubResolver{
		response: mustDNSResponse(t, "gist.github.com.", "140.82.112.7", 30),
	}
	proxy := DNSProxy{
		Policy:   engine,
		Tracker:  tracker,
		Resolver: resolver,
		Summary:  summary,
		Now:      func() time.Time { return time.Unix(100, 0) },
	}

	reply, err := proxy.HandleQuery(context.Background(), mustDNSQuery(t, "gist.github.com."))
	if err != nil {
		t.Fatalf("HandleQuery() error = %v", err)
	}
	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("Rcode = %d, want refused", reply.Rcode)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want 0", resolver.calls)
	}

	assertSummaryReportContains(t, summary, "dns  gist.github.com:53 policy=denied count=1")
}

func TestDNSProxyLogsWouldDenyInAuditMode(t *testing.T) {
	tracker := NewTracker(60 * time.Second)
	summary := NewSummary()
	engine := NewPolicyEngine(PolicyConfig{
		Audit:     true,
		Endpoints: []EndpointRule{{Host: "api.github.com", Port: 443}},
	}, tracker)
	resolver := &stubResolver{
		response: mustDNSResponse(t, "gist.github.com.", "140.82.112.7", 30),
	}
	var events bytes.Buffer
	proxy := DNSProxy{
		Policy:   engine,
		Tracker:  tracker,
		Resolver: resolver,
		Summary:  summary,
		Events:   NewEventLogger(&events),
		Now:      func() time.Time { return time.Unix(100, 0) },
	}

	reply, err := proxy.HandleQuery(context.Background(), mustDNSQuery(t, "gist.github.com."))
	if err != nil {
		t.Fatalf("HandleQuery() error = %v", err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want success", reply.Rcode)
	}

	got := events.String()
	if !strings.HasPrefix(got, "\r\x1b[2K[keel:dns] ") {
		t.Fatalf("events = %q, want line-clearing keel dns log", got)
	}
	if !strings.Contains(got, "would_deny domain=gist.github.com answers=1 rule=default reason=host not covered by endpoint") {
		t.Fatalf("events = %q, want would_deny audit log", got)
	}
}

func mustDNSQuery(t *testing.T, name string) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	return msg
}

func mustDNSResponse(t *testing.T, name, ip string, ttl uint32) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetReply(mustDNSQuery(t, name))
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: net.ParseIP(ip),
	})
	return msg
}

func assertSummaryReportContains(t *testing.T, summary *Summary, want string) {
	t.Helper()

	var buf bytes.Buffer
	if err := summary.WriteReport(&buf); err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("summary report = %q, want substring %q", buf.String(), want)
	}
}
