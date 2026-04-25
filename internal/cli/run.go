package cli

import (
	"context"

	"github.com/moolen/keel/internal/config"
)

type RunRequest struct {
	Config  config.Config
	Command []string
}

type Runner interface {
	Run(context.Context, RunRequest) error
}

type NopRunner struct{}

func (NopRunner) Run(_ context.Context, _ RunRequest) error {
	return nil
}
