package vm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
)

type GuestNetwork struct {
	TapName    string
	MACAddress string
	HostCIDR   string
	SubnetCIDR string
	GuestIP    net.IPNet
	Gateway    net.IP
}

type TapManager struct {
	Run      func(context.Context, string, ...string) error
	UserName func() string
	Suffix   func() string
}

func (m TapManager) Prepare(ctx context.Context) (*GuestNetwork, func(), error) {
	suffix := m.suffix()
	network, err := newGuestNetwork(suffix)
	if err != nil {
		return nil, nil, err
	}
	userName := m.userName()
	if userName == "" {
		return nil, nil, fmt.Errorf("USER is not set")
	}

	run := m.run
	commands := [][]string{
		{"sudo", "ip", "tuntap", "add", "dev", network.TapName, "mode", "tap", "user", userName},
		{"sudo", "ip", "addr", "add", network.HostCIDR, "dev", network.TapName},
		{"sudo", "ip", "link", "set", "dev", network.TapName, "up"},
		{"sudo", "iptables", "-w", "-A", "INPUT", "-i", network.TapName, "-j", "DROP"},
		{"sudo", "iptables", "-w", "-A", "FORWARD", "-i", network.TapName, "-j", "DROP"},
		{"sudo", "iptables", "-w", "-A", "FORWARD", "-o", network.TapName, "-j", "DROP"},
		{"sudo", "ip6tables", "-w", "-A", "INPUT", "-i", network.TapName, "-j", "DROP"},
		{"sudo", "ip6tables", "-w", "-A", "FORWARD", "-i", network.TapName, "-j", "DROP"},
		{"sudo", "ip6tables", "-w", "-A", "FORWARD", "-o", network.TapName, "-j", "DROP"},
	}
	for _, command := range commands {
		if err := run(ctx, command[0], command[1:]...); err != nil {
			return nil, nil, err
		}
	}

	cleanup := func() {
		for _, command := range [][]string{
			{"sudo", "ip6tables", "-w", "-D", "FORWARD", "-o", network.TapName, "-j", "DROP"},
			{"sudo", "ip6tables", "-w", "-D", "FORWARD", "-i", network.TapName, "-j", "DROP"},
			{"sudo", "ip6tables", "-w", "-D", "INPUT", "-i", network.TapName, "-j", "DROP"},
			{"sudo", "iptables", "-w", "-D", "FORWARD", "-o", network.TapName, "-j", "DROP"},
			{"sudo", "iptables", "-w", "-D", "FORWARD", "-i", network.TapName, "-j", "DROP"},
			{"sudo", "iptables", "-w", "-D", "INPUT", "-i", network.TapName, "-j", "DROP"},
			{"sudo", "ip", "link", "delete", "dev", network.TapName},
		} {
			_ = run(context.Background(), command[0], command[1:]...)
		}
	}
	return network, cleanup, nil
}

func (m TapManager) run(ctx context.Context, name string, args ...string) error {
	if m.Run != nil {
		return m.Run(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, output)
	}
	return nil
}

func (m TapManager) userName() string {
	if m.UserName != nil {
		return m.UserName()
	}
	return os.Getenv("USER")
}

func (m TapManager) suffix() string {
	if m.Suffix != nil {
		return m.Suffix()
	}
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "000001"
	}
	return hex.EncodeToString(buf)
}

func newGuestNetwork(suffix string) (*GuestNetwork, error) {
	seed, err := hex.DecodeString(suffix)
	if err != nil || len(seed) < 3 {
		return nil, fmt.Errorf("invalid tap suffix %q", suffix)
	}

	tapName := "keel" + suffix
	if len(tapName) > 15 {
		tapName = tapName[:15]
	}

	subnetBase := byte(seed[2] & 0xfc)
	subnetCIDR := fmt.Sprintf("172.22.%d.%d/30", seed[1], subnetBase)
	gateway := net.ParseIP(fmt.Sprintf("172.22.%d.%d", seed[1], subnetBase+1))
	guestIP := net.ParseIP(fmt.Sprintf("172.22.%d.%d", seed[1], subnetBase+2))

	return &GuestNetwork{
		TapName:    tapName,
		MACAddress: fmt.Sprintf("02:fc:%02x:%02x:%02x:01", seed[0], seed[1], seed[2]),
		HostCIDR:   gateway.String() + "/30",
		SubnetCIDR: subnetCIDR,
		GuestIP: net.IPNet{
			IP:   guestIP,
			Mask: net.CIDRMask(30, 32),
		},
		Gateway: gateway,
	}, nil
}
