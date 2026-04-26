package runtimeenv

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/moolen/keel/internal/config"
)

func Resolve(cfg config.EnvConfig) (map[string]string, error) {
	out := map[string]string{}
	for key, value := range cfg.Static {
		out[key] = value
	}
	for key, hostKey := range cfg.FromHost {
		value, ok := os.LookupEnv(hostKey)
		if !ok {
			return nil, fmt.Errorf("env.from_host.%s requires host env %s", key, hostKey)
		}
		out[key] = value
	}
	keys := make([]string, 0, len(cfg.FromCommand))
	for key := range cfg.FromCommand {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, err := resolveCommand(cfg.FromCommand[key])
		if err != nil {
			return nil, fmt.Errorf("env.from_command.%s: %w", key, err)
		}
		out[key] = value
	}
	return out, nil
}

func resolveCommand(cfg config.EnvCommand) (string, error) {
	var cmd *exec.Cmd
	switch {
	case len(cfg.Command) > 0:
		cmd = exec.Command(cfg.Command[0], cfg.Command[1:]...)
	case cfg.Shell != "":
		cmd = exec.Command("/bin/sh", "-lc", cfg.Shell)
	default:
		return "", fmt.Errorf("missing command")
	}
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("%w: %s", err, bytes.TrimSpace(exitErr.Stderr))
		}
		return "", err
	}
	value := string(output)
	value = strings.TrimSuffix(value, "\r\n")
	value = strings.TrimSuffix(value, "\n")
	if strings.Contains(value, "\n") {
		return "", fmt.Errorf("stdout must be a single line")
	}
	return value, nil
}
