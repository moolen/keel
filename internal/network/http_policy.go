package network

import (
	"fmt"
	"path"
	"strings"
)

type HTTPRequest struct {
	Host   string
	Method string
	Path   string
}

type HTTPRule struct {
	Action  string
	Host    string
	Methods []string
	Paths   []string
}

type HTTPPolicyConfig struct {
	Default string
	Rules   []HTTPRule
}

type HTTPPolicy struct {
	cfg HTTPPolicyConfig
}

func NewHTTPPolicy(cfg HTTPPolicyConfig) *HTTPPolicy {
	if strings.TrimSpace(cfg.Default) == "" {
		cfg.Default = "deny"
	}
	return &HTTPPolicy{cfg: cfg}
}

func (p *HTTPPolicy) Evaluate(req HTTPRequest) Decision {
	req.Host = normalizeName(req.Host)
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	req.Path = normalizeHTTPPath(req.Path)

	for _, rule := range p.cfg.Rules {
		if !matchHTTPRule(rule, req) {
			continue
		}
		return Decision{
			Allowed: strings.EqualFold(strings.TrimSpace(rule.Action), "allow"),
			Reason:  "http rule matched",
			Rule:    fmt.Sprintf("%s %s %s", rule.Host, strings.Join(rule.Methods, ","), strings.Join(rule.Paths, ",")),
		}
	}

	return Decision{
		Allowed: strings.EqualFold(strings.TrimSpace(p.cfg.Default), "allow"),
		Reason:  "http default",
		Rule:    "default",
	}
}

func matchHTTPRule(rule HTTPRule, req HTTPRequest) bool {
	return matchHTTPHost(rule.Host, req.Host) &&
		matchHTTPMethod(rule.Methods, req.Method) &&
		matchHTTPPath(rule.Paths, req.Path)
}

func matchHTTPHost(pattern string, host string) bool {
	pattern = normalizeName(pattern)
	if pattern == "" {
		return true
	}
	ok, err := path.Match(pattern, host)
	return err == nil && ok
}

func matchHTTPMethod(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, allowed := range methods {
		if strings.EqualFold(strings.TrimSpace(allowed), method) {
			return true
		}
	}
	return false
}

func matchHTTPPath(patterns []string, reqPath string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if matchHTTPPathPattern(normalizeHTTPPath(pattern), reqPath) {
			return true
		}
	}
	return false
}

func matchHTTPPathPattern(pattern string, reqPath string) bool {
	if pattern == "" {
		return reqPath == "/"
	}
	if pattern == "*" {
		return true
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == reqPath
	}

	index := 0
	if !strings.HasPrefix(reqPath, parts[0]) {
		return false
	}
	index = len(parts[0])

	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		offset := strings.Index(reqPath[index:], part)
		if offset < 0 {
			return false
		}
		index += offset + len(part)
	}

	last := parts[len(parts)-1]
	if last == "" {
		return true
	}

	return strings.HasSuffix(reqPath, last)
}

func normalizeHTTPPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}

	if cut := strings.IndexAny(value, "?#"); cut >= 0 {
		value = value[:cut]
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}

	cleaned := path.Clean(value)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}
