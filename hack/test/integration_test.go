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
