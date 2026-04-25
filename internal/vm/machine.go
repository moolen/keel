package vm

import (
	"context"
	"errors"

	"github.com/moolen/keel/internal/config"
)

var ErrNotImplemented = errors.New("vm lifecycle not implemented yet")

type Machine struct {
	Config config.Config
}

func NewMachine(cfg config.Config) *Machine {
	return &Machine{Config: cfg}
}

func (m *Machine) Run(context.Context) error {
	return ErrNotImplemented
}
