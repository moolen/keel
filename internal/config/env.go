package config

import "gopkg.in/yaml.v3"

func (cfg *EnvConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		type rawEnv EnvConfig
		var out rawEnv
		if err := node.Decode(&out); err != nil {
			return err
		}
		*cfg = EnvConfig(out)
		return nil
	}

	legacy := true
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "static", "from_host", "from_command":
			legacy = false
		}
	}
	if legacy {
		var static map[string]string
		if err := node.Decode(&static); err != nil {
			return err
		}
		cfg.Static = static
		cfg.FromHost = nil
		cfg.FromCommand = nil
		return nil
	}

	type rawEnv EnvConfig
	var out rawEnv
	if err := node.Decode(&out); err != nil {
		return err
	}
	*cfg = EnvConfig(out)
	return nil
}

func (cfg EnvConfig) HasValues() bool {
	return len(cfg.Static) > 0 || len(cfg.FromHost) > 0 || len(cfg.FromCommand) > 0
}
