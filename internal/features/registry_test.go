package features

import "testing"

func TestRegistryValidatesDockerConfig(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(NewDockerFeature()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	err := registry.Validate([]ConfiguredFeature{
		{
			Name: "docker",
			Config: map[string]any{
				"storage_driver": "overlay2",
				"registry_mirrors": []any{
					"https://mirror.gcr.io",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRegistryRejectsUnknownFeature(t *testing.T) {
	registry := NewRegistry()

	err := registry.Validate([]ConfiguredFeature{{Name: "unknown"}})
	if err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}
}
