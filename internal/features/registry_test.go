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

func TestRegistryAppliesRootfsPreparation(t *testing.T) {
	registry := NewRegistry()
	feature := &stubFeature{name: "stub"}
	if err := registry.Register(feature); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	err := registry.PrepareRootfs("/tmp/rootfs.ext4", []ConfiguredFeature{{
		Name: "stub",
		Config: map[string]any{
			"value": "x",
		},
	}})
	if err != nil {
		t.Fatalf("PrepareRootfs() error = %v", err)
	}
	if feature.prepareRootfsPath != "/tmp/rootfs.ext4" {
		t.Fatalf("prepareRootfsPath = %q, want /tmp/rootfs.ext4", feature.prepareRootfsPath)
	}
	if got := feature.prepareConfig["value"]; got != "x" {
		t.Fatalf("prepareConfig[value] = %#v, want x", got)
	}
}

func TestRegistryRejectsUnknownFeature(t *testing.T) {
	registry := NewRegistry()

	err := registry.Validate([]ConfiguredFeature{{Name: "unknown"}})
	if err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}
}

type stubFeature struct {
	name              string
	prepareRootfsPath string
	prepareConfig     map[string]any
}

func (s *stubFeature) Name() string {
	return s.name
}

func (s *stubFeature) ValidateConfig(map[string]any) error {
	return nil
}

func (s *stubFeature) PrepareRootfs(rootfsPath string, config map[string]any) error {
	s.prepareRootfsPath = rootfsPath
	s.prepareConfig = config
	return nil
}
