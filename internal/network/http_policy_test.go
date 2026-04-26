package network

import "testing"

func TestHTTPPolicyFirstMatchWins(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "deny",
		Rules: []HTTPRule{
			{Action: "deny", Host: "*.github.com", Methods: []string{"POST"}, Paths: []string{"/*"}},
			{Action: "allow", Host: "api.github.com", Methods: []string{"POST"}, Paths: []string{"/repos/*"}},
		},
	})

	decision := engine.Evaluate(HTTPRequest{
		Host:   "api.github.com",
		Method: "POST",
		Path:   "/repos/openai/openai",
	})
	if decision.Allowed {
		t.Fatalf("decision = %#v, want denied by first match", decision)
	}
}

func TestHTTPPolicyMatchesGlobPath(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "deny",
		Rules: []HTTPRule{
			{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/repos/*"}},
		},
	})

	decision := engine.Evaluate(HTTPRequest{
		Host:   "api.github.com",
		Method: "GET",
		Path:   "/repos/moolen/keel",
	})
	if !decision.Allowed {
		t.Fatalf("decision = %#v, want allowed", decision)
	}
}

func TestHTTPPolicyNormalizesHostByStrippingPort(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "deny",
		Rules: []HTTPRule{
			{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/*"}},
			{Action: "allow", Host: "localhost", Methods: []string{"GET"}, Paths: []string{"/*"}},
			{Action: "allow", Host: "::1", Methods: []string{"GET"}, Paths: []string{"/*"}},
		},
	})

	tests := []HTTPRequest{
		{Host: "api.github.com:443", Method: "GET", Path: "/"},
		{Host: "localhost:8443", Method: "GET", Path: "/"},
		{Host: "[::1]:8443", Method: "GET", Path: "/"},
	}

	for _, req := range tests {
		decision := engine.Evaluate(req)
		if !decision.Allowed {
			t.Fatalf("request %#v decision = %#v, want allowed", req, decision)
		}
	}
}

func TestHTTPPolicyNormalizesMethod(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "deny",
		Rules: []HTTPRule{
			{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/*"}},
		},
	})

	decision := engine.Evaluate(HTTPRequest{
		Host:   "api.github.com",
		Method: " get ",
		Path:   "/",
	})
	if !decision.Allowed {
		t.Fatalf("decision = %#v, want allowed", decision)
	}
}

func TestHTTPPolicyStripsQueryFromPath(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "deny",
		Rules: []HTTPRule{
			{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/repos/openai/keel"}},
		},
	})

	decision := engine.Evaluate(HTTPRequest{
		Host:   "api.github.com",
		Method: "GET",
		Path:   "/repos/openai/keel?ref=main",
	})
	if !decision.Allowed {
		t.Fatalf("decision = %#v, want allowed", decision)
	}
}

func TestHTTPPolicyCleansPath(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "deny",
		Rules: []HTTPRule{
			{Action: "allow", Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/repos/keel"}},
		},
	})

	decision := engine.Evaluate(HTTPRequest{
		Host:   "api.github.com",
		Method: "GET",
		Path:   "/repos/openai/../keel",
	})
	if !decision.Allowed {
		t.Fatalf("decision = %#v, want allowed after path cleaning", decision)
	}
}

func TestHTTPPolicyUsesDefaultWhenNoRuleMatches(t *testing.T) {
	engine := NewHTTPPolicy(HTTPPolicyConfig{
		Default: "allow",
		Rules: []HTTPRule{
			{Action: "deny", Host: "api.github.com", Methods: []string{"POST"}, Paths: []string{"/repos/*"}},
		},
	})

	decision := engine.Evaluate(HTTPRequest{
		Host:   "api.github.com",
		Method: "GET",
		Path:   "/users/openai",
	})
	if !decision.Allowed {
		t.Fatalf("decision = %#v, want allowed by default", decision)
	}
	if decision.Rule != "default" {
		t.Fatalf("decision.Rule = %q, want default", decision.Rule)
	}
	if decision.Reason != "http default" {
		t.Fatalf("decision.Reason = %q, want http default", decision.Reason)
	}
}
