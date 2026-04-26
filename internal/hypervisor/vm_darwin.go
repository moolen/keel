//go:build darwin

package hypervisor

import (
	"context"
	"fmt"
	"net"
)

type stubVM struct{}

func New(Config) (VM, error) {
	return stubVM{}, nil
}

func (stubVM) Start(context.Context) error {
	return fmt.Errorf("macOS hypervisor backend is not implemented yet")
}

func (stubVM) Stop(context.Context) error {
	return nil
}

func (stubVM) Wait(context.Context) error {
	return fmt.Errorf("macOS hypervisor backend is not implemented yet")
}

func (stubVM) VSockListen(uint32) (net.Listener, error) {
	return nil, fmt.Errorf("macOS hypervisor backend is not implemented yet")
}

func (stubVM) VSockConnect(uint32) (net.Conn, error) {
	return nil, fmt.Errorf("macOS hypervisor backend is not implemented yet")
}
