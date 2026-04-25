package vm

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestTapManagerPrepareConfiguresTapAndNAT(t *testing.T) {
	var commands []string
	manager := TapManager{
		Run: func(_ context.Context, name string, args ...string) error {
			commands = append(commands, name+" "+strings.Join(args, " "))
			return nil
		},
		UserName: func() string { return "moritz" },
		Suffix:   func() string { return "a1b2c3" },
	}

	network, cleanup, err := manager.Prepare(context.Background())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup = nil, want non-nil")
	}
	if got, want := network.TapName, "keela1b2c3"; got != want {
		t.Fatalf("TapName = %q, want %q", got, want)
	}
	if got, want := network.HostCIDR, "172.22.178.193/30"; got != want {
		t.Fatalf("HostCIDR = %q, want %q", got, want)
	}
	if got, want := network.SubnetCIDR, "172.22.178.192/30"; got != want {
		t.Fatalf("SubnetCIDR = %q, want %q", got, want)
	}
	if got, want := network.Gateway.String(), "172.22.178.193"; got != want {
		t.Fatalf("Gateway = %q, want %q", got, want)
	}
	if got, want := network.GuestIP.String(), "172.22.178.194/30"; got != want {
		t.Fatalf("GuestIP = %q, want %q", got, want)
	}
	if got, want := network.MACAddress, "02:fc:a1:b2:c3:01"; got != want {
		t.Fatalf("MACAddress = %q, want %q", got, want)
	}

	want := []string{
		"sudo sysctl -w net.ipv4.ip_forward=1",
		"sudo ip tuntap add dev keela1b2c3 mode tap user moritz",
		"sudo ip addr add 172.22.178.193/30 dev keela1b2c3",
		"sudo ip link set dev keela1b2c3 up",
		"sudo iptables -w -A FORWARD -i keela1b2c3 -j ACCEPT",
		"sudo iptables -w -A FORWARD -o keela1b2c3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"sudo iptables -w -t nat -A POSTROUTING -s 172.22.178.192/30 ! -d 172.22.178.192/30 -j MASQUERADE",
	}
	if diff := compareCommands(want, commands); diff != "" {
		t.Fatalf("Prepare() commands mismatch:\n%s", diff)
	}

	commands = nil
	cleanup()
	wantCleanup := []string{
		"sudo iptables -w -t nat -D POSTROUTING -s 172.22.178.192/30 ! -d 172.22.178.192/30 -j MASQUERADE",
		"sudo iptables -w -D FORWARD -o keela1b2c3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"sudo iptables -w -D FORWARD -i keela1b2c3 -j ACCEPT",
		"sudo ip link delete dev keela1b2c3",
	}
	if diff := compareCommands(wantCleanup, commands); diff != "" {
		t.Fatalf("cleanup commands mismatch:\n%s", diff)
	}
}

func compareCommands(want, got []string) string {
	if len(want) != len(got) {
		return fmt.Sprintf("len = %d, want %d\n got: %#v", len(got), len(want), got)
	}
	for i := range want {
		if want[i] != got[i] {
			return fmt.Sprintf("command %d = %q, want %q", i, got[i], want[i])
		}
	}
	return ""
}
