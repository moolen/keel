package features

import (
	"fmt"
	"sort"
)

type ConfiguredFeature struct {
	Name   string
	Config map[string]any
}

type NormalizedFeature struct {
	Name   string
	Config map[string]any
}

type Feature interface {
	Name() string
	ValidateConfig(map[string]any) error
	NormalizeConfig(map[string]any) (NormalizedFeature, error)
	PrepareRootfs(string, map[string]any) error
}

type Registry struct {
	features map[string]Feature
}

func NewRegistry() *Registry {
	return &Registry{features: map[string]Feature{}}
}

func (r *Registry) Register(feature Feature) error {
	if _, exists := r.features[feature.Name()]; exists {
		return fmt.Errorf("feature %q already registered", feature.Name())
	}
	r.features[feature.Name()] = feature
	return nil
}

func (r *Registry) Validate(configured []ConfiguredFeature) error {
	for _, item := range configured {
		feature, ok := r.features[item.Name]
		if !ok {
			return fmt.Errorf("unknown feature %q (available: %v)", item.Name, r.Names())
		}
		if err := feature.ValidateConfig(item.Config); err != nil {
			return fmt.Errorf("feature %q: %w", item.Name, err)
		}
	}
	return nil
}

func (r *Registry) Normalize(configured []ConfiguredFeature) ([]NormalizedFeature, error) {
	normalized := make([]NormalizedFeature, 0, len(configured))
	for _, item := range configured {
		feature, ok := r.features[item.Name]
		if !ok {
			return nil, fmt.Errorf("unknown feature %q (available: %v)", item.Name, r.Names())
		}
		normalizedFeature, err := feature.NormalizeConfig(item.Config)
		if err != nil {
			return nil, fmt.Errorf("feature %q: %w", item.Name, err)
		}
		normalized = append(normalized, normalizedFeature)
	}
	return normalized, nil
}

func (r *Registry) PrepareRootfs(rootfsPath string, configured []ConfiguredFeature) error {
	for _, item := range configured {
		feature, ok := r.features[item.Name]
		if !ok {
			return fmt.Errorf("unknown feature %q (available: %v)", item.Name, r.Names())
		}
		if err := feature.PrepareRootfs(rootfsPath, item.Config); err != nil {
			return fmt.Errorf("feature %q: %w", item.Name, err)
		}
	}
	return nil
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.features))
	for name := range r.features {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
