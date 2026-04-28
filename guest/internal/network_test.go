package internal

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestEnsureLoopbackUpSetsIFFUP(t *testing.T) {
	var socketDomain int
	var socketType int
	var socketProto int
	var ioctlReq uint
	var ioctlFlags uint16
	var ioctlName string
	var closedFD int

	err := ensureLoopbackUpWith(linkOps{
		socket: func(domain, typ, proto int) (int, error) {
			socketDomain = domain
			socketType = typ
			socketProto = proto
			return 42, nil
		},
		newIfreq: unix.NewIfreq,
		ioctlIfreq: func(fd int, req uint, ifr *unix.Ifreq) error {
			if fd != 42 {
				t.Fatalf("fd = %d, want 42", fd)
			}
			ioctlReq = req
			ioctlFlags = ifr.Uint16()
			ioctlName = ifr.Name()
			return nil
		},
		close: func(fd int) error {
			closedFD = fd
			return nil
		},
	})
	if err != nil {
		t.Fatalf("ensureLoopbackUpWith() error = %v", err)
	}
	if socketDomain != unix.AF_INET || socketType != unix.SOCK_DGRAM || socketProto != 0 {
		t.Fatalf("socket args = (%d,%d,%d)", socketDomain, socketType, socketProto)
	}
	if ioctlReq != unix.SIOCSIFFLAGS {
		t.Fatalf("ioctl req = %#x, want %#x", ioctlReq, unix.SIOCSIFFLAGS)
	}
	if ioctlName != "lo" {
		t.Fatalf("ifreq name = %q, want lo", ioctlName)
	}
	if ioctlFlags&unix.IFF_UP == 0 {
		t.Fatalf("IFF_UP not set in flags %#x", ioctlFlags)
	}
	if closedFD != 42 {
		t.Fatalf("closed fd = %d, want 42", closedFD)
	}
}
