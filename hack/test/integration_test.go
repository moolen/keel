package test

import "testing"

func TestDockerBuildProxyOnlyE2E(t *testing.T) {
	if !e2eEnabled(t) {
		t.Skip("set KEEL_E2E=1 to run Firecracker e2e coverage")
	}
	if err := runDockerBuildProxyOnlyE2E(t); err != nil {
		t.Fatal(err)
	}
}

func TestMITMHTTPPolicyE2E(t *testing.T) {
	if !e2eEnabled(t) {
		t.Skip("set KEEL_E2E=1 to run Firecracker e2e coverage")
	}
	if err := runMITMHTTPPolicyE2E(t); err != nil {
		t.Fatal(err)
	}
}

func TestDockerRunProxyOnlyE2E(t *testing.T) {
	if !e2eEnabled(t) {
		t.Skip("set KEEL_E2E=1 to run Firecracker e2e coverage")
	}
	if err := runDockerRunProxyOnlyE2E(t); err != nil {
		t.Fatal(err)
	}
}
