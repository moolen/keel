package network

import (
	"fmt"
	"net"
	"path"
	"strings"
	"time"
)

type RuleSet struct {
	Allowed []string
	Denied  []string
}

type CIDRRuleSet struct {
	Allowed []string
	Denied  []string
}

type PolicyConfig struct {
	DNS         RuleSet
	TCP         CIDRRuleSet
	TLS         RuleSet
	DenyIfNoSNI bool
}

type Decision struct {
	Allowed bool
	Reason  string
	Rule    string
}

type PolicyEngine struct {
	config  PolicyConfig
	tracker *Tracker
}

func NewPolicyEngine(cfg PolicyConfig, tracker *Tracker) *PolicyEngine {
	return &PolicyEngine{config: cfg, tracker: tracker}
}

func (e *PolicyEngine) EvaluateDNS(domain string) Decision {
	domain = normalizeName(domain)
	if rule, ok := matchAny(domain, e.config.DNS.Denied); ok {
		return Decision{Reason: "dns denied", Rule: rule}
	}
	if len(e.config.DNS.Allowed) == 0 {
		return Decision{Allowed: true, Reason: "dns default allow", Rule: "default"}
	}
	if rule, ok := matchAny(domain, e.config.DNS.Allowed); ok {
		return Decision{Allowed: true, Reason: "dns allowed", Rule: rule}
	}
	return Decision{Reason: "dns not allowlisted", Rule: "default"}
}

func (e *PolicyEngine) EvaluateTCP(ip net.IP, port int, sni string, now time.Time) Decision {
	if ip == nil {
		return Decision{Reason: "missing destination ip", Rule: "default"}
	}
	for _, rule := range e.config.TCP.Denied {
		if cidrContains(rule, ip) {
			return Decision{Reason: "tcp denied by cidr", Rule: rule}
		}
	}

	var domains []string
	if e.tracker != nil {
		domains = e.tracker.Domains(ip, now)
	}

	if len(domains) > 0 {
		if port == 443 {
			if e.config.DenyIfNoSNI && sni == "" {
				return Decision{Reason: "tls sni required", Rule: "deny_if_no_sni"}
			}
			if sni != "" {
				if rule, ok := matchAny(sni, e.config.TLS.Denied); ok {
					return Decision{Reason: "tls denied by sni", Rule: rule}
				}
				if len(e.config.TLS.Allowed) > 0 {
					if rule, ok := matchAny(sni, e.config.TLS.Allowed); ok {
						if !containsName(domains, sni) {
							return Decision{Reason: "sni does not match resolved domain", Rule: rule}
						}
						return Decision{Allowed: true, Reason: "tcp allowed via dns correlation", Rule: fmt.Sprintf("dns:%s", sni)}
					}
					return Decision{Reason: "tls sni not allowlisted", Rule: "default"}
				}
			}
		}
		return Decision{Allowed: true, Reason: "tcp allowed via dns correlation", Rule: fmt.Sprintf("dns:%s", domains[0])}
	}

	for _, rule := range e.config.TCP.Allowed {
		if cidrContains(rule, ip) {
			return Decision{Allowed: true, Reason: "tcp allowed by cidr", Rule: rule}
		}
	}

	return Decision{Reason: "tcp destination not correlated", Rule: "default"}
}

func matchAny(name string, patterns []string) (string, bool) {
	name = normalizeName(name)
	for _, pattern := range patterns {
		pattern = normalizeName(pattern)
		ok, err := path.Match(pattern, name)
		if err == nil && ok {
			return pattern, true
		}
	}
	return "", false
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func containsName(domains []string, sni string) bool {
	for _, domain := range domains {
		if normalizeName(domain) == normalizeName(sni) {
			return true
		}
	}
	return false
}

func cidrContains(cidr string, ip net.IP) bool {
	_, network, err := net.ParseCIDR(cidr)
	return err == nil && network.Contains(ip)
}
