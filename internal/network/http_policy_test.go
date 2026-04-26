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
