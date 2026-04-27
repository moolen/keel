package internal

import (
	"errors"
	"fmt"
	"math/bits"
	"net"
	"os"
	"os/exec"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	bpfInterceptionRoot     = "/sys/fs/cgroup/keel"
	bpfWorkloadCgroupPath   = bpfInterceptionRoot + "/workload"
	bpfInterceptionMaxFlows = 4096
)

type bpfOriginalDestination struct {
	IP4  uint32
	Port uint32
}

type bpfCgroupInterception struct {
	workload *os.File
	pending  *ebpf.Map
	handoff  *ebpf.Map
	connect4 *ebpf.Program
	sockops  *ebpf.Program
	links    []link.Link
}

func newBPFCgroupInterception() (trafficInterception, error) {
	if err := os.MkdirAll(bpfWorkloadCgroupPath, 0o755); err != nil {
		return nil, err
	}

	workload, err := os.Open(bpfWorkloadCgroupPath)
	if err != nil {
		return nil, err
	}

	pending, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "keel_pending",
		Type:       ebpf.LRUHash,
		KeySize:    8,
		ValueSize:  uint32(unsafe.Sizeof(bpfOriginalDestination{})),
		MaxEntries: bpfInterceptionMaxFlows,
	})
	if err != nil {
		_ = workload.Close()
		return nil, err
	}

	handoff, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "keel_handoff",
		Type:       ebpf.LRUHash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(bpfOriginalDestination{})),
		MaxEntries: bpfInterceptionMaxFlows,
	})
	if err != nil {
		_ = pending.Close()
		_ = workload.Close()
		return nil, err
	}

	connect4, err := newConnect4Program(pending)
	if err != nil {
		_ = handoff.Close()
		_ = pending.Close()
		_ = workload.Close()
		return nil, err
	}

	sockops, err := newSockopsProgram(pending, handoff)
	if err != nil {
		_ = connect4.Close()
		_ = handoff.Close()
		_ = pending.Close()
		_ = workload.Close()
		return nil, err
	}

	connectLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    bpfWorkloadCgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: connect4,
	})
	if err != nil {
		_ = sockops.Close()
		_ = connect4.Close()
		_ = handoff.Close()
		_ = pending.Close()
		_ = workload.Close()
		return nil, err
	}

	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    bpfWorkloadCgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: sockops,
	})
	if err != nil {
		_ = connectLink.Close()
		_ = sockops.Close()
		_ = connect4.Close()
		_ = handoff.Close()
		_ = pending.Close()
		_ = workload.Close()
		return nil, err
	}

	return &bpfCgroupInterception{
		workload: workload,
		pending:  pending,
		handoff:  handoff,
		connect4: connect4,
		sockops:  sockops,
		links:    []link.Link{connectLink, sockopsLink},
	}, nil
}

func (b *bpfCgroupInterception) mode() string { return bpfCgroupMode }

func (b *bpfCgroupInterception) workloadCgroupFD() int {
	if b == nil || b.workload == nil {
		return 0
	}
	return int(b.workload.Fd())
}

func (b *bpfCgroupInterception) attachCommand(*exec.Cmd) {}

func (b *bpfCgroupInterception) resolveOriginalDestination(conn net.Conn) (string, bool, error) {
	remoteHost, remotePort, err := splitTCPRemoteAddr(conn.RemoteAddr())
	if err != nil {
		return "", false, err
	}
	if !remoteHost.IsLoopback() {
		return "", false, nil
	}

	key := uint32(remotePort)
	var destination bpfOriginalDestination
	if err := b.handoff.LookupAndDelete(&key, &destination); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return "", false, nil
		}
		return "", false, err
	}

	formatted, err := formatBPFOriginalDestination(destination)
	if err != nil {
		return "", false, err
	}
	return formatted, true, nil
}

func (b *bpfCgroupInterception) close() error {
	var err error
	for _, item := range b.links {
		err = errors.Join(err, item.Close())
	}
	if b.sockops != nil {
		err = errors.Join(err, b.sockops.Close())
	}
	if b.connect4 != nil {
		err = errors.Join(err, b.connect4.Close())
	}
	if b.handoff != nil {
		err = errors.Join(err, b.handoff.Close())
	}
	if b.pending != nil {
		err = errors.Join(err, b.pending.Close())
	}
	if b.workload != nil {
		err = errors.Join(err, b.workload.Close())
	}
	return err
}

func splitTCPRemoteAddr(addr net.Addr) (net.IP, int, error) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("transparent destination requires *net.TCPAddr, got %T", addr)
	}
	return tcpAddr.IP, tcpAddr.Port, nil
}

func formatBPFOriginalDestination(destination bpfOriginalDestination) (string, error) {
	port := int(bits.ReverseBytes16(uint16(destination.Port)))
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid transparent destination port %d", port)
	}
	ip := net.IPv4(
		byte(destination.IP4),
		byte(destination.IP4>>8),
		byte(destination.IP4>>16),
		byte(destination.IP4>>24),
	)
	if ip == nil || ip.IsUnspecified() {
		return "", errors.New("invalid transparent destination ip")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func newConnect4Program(pending *ebpf.Map) (*ebpf.Program, error) {
	offsets := sockAddrOffsets()
	loopbackIP := storedNetworkUint32(0x7f000001)
	proxyPort := storedNetworkPortUint32(uint16(tcpProxyPort))

	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, offsets.protocol, asm.Word),
		asm.JNE.Imm(asm.R2, unix.IPPROTO_TCP, "allow"),
		asm.LoadMem(asm.R2, asm.R6, offsets.userIP4, asm.Word),
		asm.JNE.Imm(asm.R2, int32(loopbackIP), "capture"),
		asm.LoadMem(asm.R2, asm.R6, offsets.userPort, asm.Word),
		asm.JEq.Imm(asm.R2, int32(proxyPort), "allow"),

		asm.LoadMem(asm.R2, asm.R6, offsets.userIP4, asm.Word).WithSymbol("capture"),
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R6, offsets.userPort, asm.Word),
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnGetSocketCookie.Call(),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, pending.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "allow"),
		asm.Mov.Imm(asm.R2, int32(loopbackIP)),
		asm.StoreMem(asm.R6, offsets.userIP4, asm.R2, asm.Word),
		asm.Mov.Imm(asm.R2, int32(proxyPort)),
		asm.StoreMem(asm.R6, offsets.userPort, asm.R2, asm.Word),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}

	return ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "keel_c4",
		Type:         ebpf.CGroupSockAddr,
		AttachType:   ebpf.AttachCGroupInet4Connect,
		License:      "GPL",
		Instructions: insns,
	})
}

func newSockopsProgram(pending *ebpf.Map, handoff *ebpf.Map) (*ebpf.Program, error) {
	offsets := sockOpsOffsets()

	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, offsets.op, asm.Word),
		asm.JNE.Imm(asm.R2, bpfSockOpsActiveEstablished, "done"),
		asm.LoadMem(asm.R2, asm.R6, offsets.localPort, asm.Word),
		asm.StoreMem(asm.RFP, -28, asm.R2, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnGetSocketCookie.Call(),
		asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, pending.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -24),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "done"),
		asm.LoadMem(asm.R2, asm.R0, 0, asm.Word),
		asm.StoreMem(asm.RFP, -16, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R0, 4, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, handoff.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -28),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.LoadMapPtr(asm.R1, pending.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -24),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("done"),
		asm.Return(),
	}

	return ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "keel_so",
		Type:         ebpf.SockOps,
		AttachType:   ebpf.AttachCGroupSockOps,
		License:      "GPL",
		Instructions: insns,
	})
}

type bpfSockAddrLayout struct {
	UserFamily uint32
	UserIP4    uint32
	UserIP6    [4]uint32
	UserPort   uint32
	Family     uint32
	Type       uint32
	Protocol   uint32
	MsgSrcIP4  uint32
	MsgSrcIP6  [4]uint32
	Sk         uintptr
}

type bpfSockOpsLayout struct {
	Op         uint32
	Args       [4]uint32
	Family     uint32
	RemoteIP4  uint32
	LocalIP4   uint32
	RemoteIP6  [4]uint32
	LocalIP6   [4]uint32
	RemotePort uint32
	LocalPort  uint32
}

type sockAddrFieldOffsets struct {
	userIP4  int16
	userPort int16
	protocol int16
}

type sockOpsFieldOffsets struct {
	op        int16
	localPort int16
}

func sockAddrOffsets() sockAddrFieldOffsets {
	var layout bpfSockAddrLayout
	return sockAddrFieldOffsets{
		userIP4:  int16(unsafe.Offsetof(layout.UserIP4)),
		userPort: int16(unsafe.Offsetof(layout.UserPort)),
		protocol: int16(unsafe.Offsetof(layout.Protocol)),
	}
}

func sockOpsOffsets() sockOpsFieldOffsets {
	var layout bpfSockOpsLayout
	return sockOpsFieldOffsets{
		op:        int16(unsafe.Offsetof(layout.Op)),
		localPort: int16(unsafe.Offsetof(layout.LocalPort)),
	}
}

func storedNetworkUint32(value uint32) uint32 {
	return bits.ReverseBytes32(value)
}

func storedNetworkPortUint32(value uint16) uint32 {
	return uint32(bits.ReverseBytes16(value))
}

const bpfSockOpsActiveEstablished = 4
