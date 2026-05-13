package network

import (
	"fmt"
	"net"
	"path"
	"strings"
	"time"
)

type PolicyConfig struct {
	Audit     bool
	Endpoints []EndpointRule
	IPRules   []IPRule
}

type EndpointRule struct {
	Host            string
	Port            int
	RequireSNIMatch bool
	MITMRequired    bool
	HTTP            HTTPPolicyConfig
}

type IPRule struct {
	CIDR string
	Port int
}

type DNSAuthorization struct {
	Host            string
	Port            int
	RequireSNIMatch bool
	MITMRequired    bool
	HTTP            HTTPPolicyConfig
	Rule            string
}

type Decision struct {
	Allowed      bool
	WouldDeny    bool
	Reason       string
	Rule         string
	EndpointHost string
	MITMRequired bool
	HTTP         HTTPPolicyConfig
}

type PolicyEngine struct {
	config  PolicyConfig
	tracker *Tracker
}

func NewPolicyEngine(cfg PolicyConfig, tracker *Tracker) *PolicyEngine {
	return &PolicyEngine{config: cfg, tracker: tracker}
}

func (e *PolicyEngine) EvaluateDNS(domain string) (Decision, []DNSAuthorization) {
	domain = normalizeName(domain)
	var authorizations []DNSAuthorization
	for _, endpoint := range e.config.Endpoints {
		host := normalizeName(endpoint.Host)
		if !matchName(domain, host) {
			continue
		}
		rule := endpointRuleName(host, endpoint.Port)
		authorizations = append(authorizations, DNSAuthorization{
			Host:            domain,
			Port:            endpoint.Port,
			RequireSNIMatch: endpoint.RequireSNIMatch,
			MITMRequired:    endpoint.MITMRequired,
			HTTP:            endpoint.HTTP,
			Rule:            rule,
		})
	}
	if len(authorizations) == 0 {
		return e.applyAudit(Decision{Reason: "host not covered by endpoint", Rule: "default"}), nil
	}
	return Decision{
		Allowed:      true,
		Reason:       "host covered by endpoint",
		Rule:         authorizations[0].Rule,
		EndpointHost: domain,
		MITMRequired: authorizations[0].MITMRequired,
		HTTP:         authorizations[0].HTTP,
	}, authorizations
}

func (e *PolicyEngine) ObserveDNS(domain string, ips []net.IP, ttl time.Duration, now time.Time, auths []DNSAuthorization) {
	if e.tracker == nil {
		return
	}
	for _, ip := range ips {
		for _, auth := range auths {
			e.tracker.ObserveAuthorization(ip, ttl, now, auth)
		}
	}
}

func (e *PolicyEngine) EvaluateTCP(ip net.IP, port int, sni string, isTLS bool, now time.Time) Decision {
	if ip == nil {
		return e.applyAudit(Decision{Reason: "missing destination ip", Rule: "default"})
	}

	if e.tracker != nil {
		auths := e.tracker.Authorizations(ip, port, now)
		if len(auths) > 0 {
			if decision, ok := evaluateEndpointAuthorizations(auths, sni, isTLS); ok {
				return decision
			}
			return e.applyAudit(Decision{Reason: "sni does not match endpoint", Rule: auths[0].Rule, EndpointHost: auths[0].Host})
		}
	}

	for _, rule := range e.config.IPRules {
		if rule.Port == port && cidrContains(rule.CIDR, ip) {
			return Decision{
				Allowed: true,
				Reason:  "tcp allowed by direct ip rule",
				Rule:    directIPRuleName(rule.CIDR, rule.Port),
			}
		}
	}

	return e.applyAudit(Decision{Reason: "tcp destination not authorized", Rule: "default"})
}

func evaluateEndpointAuthorizations(auths []DNSAuthorization, sni string, isTLS bool) (Decision, bool) {
	normalizedSNI := normalizeName(sni)
	for _, auth := range auths {
		if isTLS && auth.RequireSNIMatch {
			if normalizedSNI == "" || normalizedSNI != normalizeName(auth.Host) {
				continue
			}
		}
		return Decision{
			Allowed:      true,
			Reason:       "tcp allowed by endpoint authorization",
			Rule:         auth.Rule,
			EndpointHost: normalizeName(auth.Host),
			MITMRequired: auth.MITMRequired,
			HTTP:         auth.HTTP,
		}, true
	}
	return Decision{}, false
}

func (e *PolicyEngine) applyAudit(decision Decision) Decision {
	if !e.config.Audit || decision.Allowed {
		return decision
	}
	decision.Allowed = true
	decision.WouldDeny = true
	return decision
}

func matchAny(name string, patterns []string) (string, bool) {
	name = normalizeName(name)
	for _, pattern := range patterns {
		pattern = normalizeName(pattern)
		if matchName(name, pattern) {
			return pattern, true
		}
	}
	return "", false
}

func matchName(name, pattern string) bool {
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func cidrContains(cidr string, ip net.IP) bool {
	_, network, err := net.ParseCIDR(cidr)
	return err == nil && network.Contains(ip)
}

func endpointRuleName(host string, port int) string {
	return fmt.Sprintf("endpoint:%s:%d", normalizeName(host), port)
}

func directIPRuleName(cidr string, port int) string {
	return fmt.Sprintf("ip:%s:%d", cidr, port)
}
