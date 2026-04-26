package hypervisor

import (
	"context"
	"net"
	"runtime"
)

// VM is the platform-agnostic virtual machine interface.
type VM interface {
	Start(context.Context) error
	Stop(context.Context) error
	Wait(context.Context) error
	VSockListen(port uint32) (net.Listener, error)
	VSockConnect(port uint32) (net.Conn, error)
}

type Config struct {
	KernelPath        string
	InitrdPath        string
	KernelArgs        string
	RootDrive         DriveConfig
	ExtraDrives       []DriveConfig
	VCPUs             int
	MemoryMB          int
	VSockCID          uint32
	RuntimeDir        string
	SocketPath        string
	VSockPath         string
	LogPath           string
	Verbose           bool
	NetworkInterfaces []NetworkInterfaceConfig
}

type DriveConfig struct {
	ID       string
	Path     string
	ReadOnly bool
	IsRoot   bool
}

type NetworkInterfaceConfig struct {
	HostDevName     string
	MACAddress      string
	IPConfiguration *IPConfiguration
}

type IPConfiguration struct {
	Address net.IPNet
	Gateway net.IP
}

func GuestArch() string {
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}
