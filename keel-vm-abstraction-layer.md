# Keel — Hypervisor Abstraction Layer

Implementation plan for the platform abstraction that lets keel run on Linux (Firecracker/KVM) and macOS (Apple Virtualization.framework) with identical UX.

---

## 1. Design Goal

All keel code above the hypervisor layer — policy engine, PTY, workspace, CLI — operates on `net.Conn` and `net.Listener`. It never imports Firecracker or Vz types. The only platform-specific code lives behind build tags in two packages.

---

## 2. Core Interface

```go
// internal/hypervisor/hypervisor.go
package hypervisor

import (
    "context"
    "net"
    "runtime"
)

// VM is the platform-agnostic virtual machine interface.
type VM interface {
    // Start boots the VM. Blocks until the guest agent signals readiness
    // on vsock port 1000, or ctx is cancelled.
    Start(ctx context.Context) error

    // Stop requests a graceful shutdown. Sends ACPI power-off to the guest,
    // waits up to the context deadline, then force-kills.
    Stop(ctx context.Context) error

    // Wait blocks until the VM process exits. Returns the VM exit status.
    Wait(ctx context.Context) error

    // VSockListen returns a listener for guest-initiated connections on
    // the given port. Must be called before Start() so the listener is
    // ready when the guest boots.
    VSockListen(port uint32) (net.Listener, error)

    // VSockConnect initiates a host→guest connection to the given port.
    // Only valid after Start() returns.
    VSockConnect(port uint32) (net.Conn, error)
}

type Config struct {
    KernelPath  string       // path to vmlinux (platform-appropriate arch)
    InitrdPath  string       // optional, used by Vz for initrd-based boot
    RootDrive   DriveConfig  // rootfs (ext4 image)
    ExtraDrives []DriveConfig
    VCPUs       int
    MemoryMB    int
    VSockCID    uint32       // Firecracker only; ignored by Vz
}

type DriveConfig struct {
    ID       string
    Path     string // path to ext4 image on host
    ReadOnly bool
}

// GuestArch returns the architecture the guest kernel must be compiled for.
func GuestArch() string {
    if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
        return "arm64"
    }
    return "amd64"
}

// New returns the platform-appropriate VM implementation.
// Build-tag dispatched: see vm_linux.go and vm_darwin.go.
func New(cfg Config) (VM, error)
```

---

## 3. Package Layout

```
internal/hypervisor/
├── hypervisor.go                 # interface, Config, GuestArch(), New() signature
├── firecracker/
│   ├── vm.go                    # //go:build linux — FirecrackerVM struct
│   ├── vsock.go                 # //go:build linux — UDS-based vsock listener/connector
│   └── doc.go                   # package doc
└── vf/
    ├── vm.go                    # //go:build darwin — VzVM struct
    ├── vsock.go                 # //go:build darwin — VirtioSocketDevice wrapper
    ├── entitlements.go          # //go:build darwin — codesign check helper
    └── doc.go                   # package doc
```

Build-tag dispatch files at the hypervisor package level:

```go
// internal/hypervisor/new_linux.go
//go:build linux

package hypervisor

import "github.com/yourusername/keel/internal/hypervisor/firecracker"

func New(cfg Config) (VM, error) {
    return firecracker.New(cfg)
}
```

```go
// internal/hypervisor/new_darwin.go
//go:build darwin

package hypervisor

import "github.com/yourusername/keel/internal/hypervisor/vf"

func New(cfg Config) (VM, error) {
    return vf.New(cfg)
}
```

---

## 4. Firecracker Backend (Linux)

### 4.1 Dependencies

- `github.com/firecracker-microvm/firecracker-go-sdk`
- Firecracker binary on `$PATH` or configured path
- `/dev/kvm` accessible

### 4.2 VM Lifecycle

```go
// internal/hypervisor/firecracker/vm.go
//go:build linux

package firecracker

type FirecrackerVM struct {
    cfg       hypervisor.Config
    machine   *firecracker.Machine
    ctx       context.Context
    cancel    context.CancelFunc
    sockPath  string // API socket path (temp file)
    vsockPath string // vsock UDS path (temp file)
    listeners map[uint32]net.Listener
    mu        sync.Mutex
}

func New(cfg hypervisor.Config) (*FirecrackerVM, error) {
    // Validate: /dev/kvm exists, firecracker binary found
    // Generate temp paths for API socket and vsock UDS
}
```

**Start flow:**
1. Create temp dir for socket files
2. Build `firecracker.Config` from `hypervisor.Config`:
   - Map `RootDrive` + `ExtraDrives` → `[]models.Drive`
   - Single `VsockDevice` with configured CID and host-side UDS path
   - No `NetworkInterfaces`
   - Set `init=/usr/local/bin/keel-agent` in boot args
3. Create `firecracker.Machine`, call `Start(ctx)`
4. Wait for guest agent readiness signal on vsock port 1000

**Stop flow:**
1. `machine.Shutdown(ctx)` (sends CtrlAltDel)
2. If context deadline exceeded, `machine.StopVMM()`
3. Clean up temp dir (socket files)

### 4.3 vsock Implementation

Firecracker exposes guest-initiated vsock connections via a UDS multiplexing convention: the host listens on `{vsock_uds_path}_{port}`.

```go
// internal/hypervisor/firecracker/vsock.go
//go:build linux

package firecracker

// VSockListen creates a Unix socket listener at {vsockPath}_{port}.
// Firecracker routes guest connections to CID 2 (host) on this port
// to the corresponding UDS.
func (vm *FirecrackerVM) VSockListen(port uint32) (net.Listener, error) {
    path := fmt.Sprintf("%s_%d", vm.vsockPath, port)
    ln, err := net.Listen("unix", path)
    if err != nil {
        return nil, fmt.Errorf("vsock listen port %d: %w", port, err)
    }
    vm.mu.Lock()
    vm.listeners[port] = ln
    vm.mu.Unlock()
    return ln, nil
}

// VSockConnect initiates a host→guest connection.
// Connects to the Firecracker vsock UDS and sends the CONNECT command.
func (vm *FirecrackerVM) VSockConnect(port uint32) (net.Conn, error) {
    conn, err := net.Dial("unix", vm.vsockPath)
    if err != nil {
        return nil, err
    }
    // Firecracker vsock connect protocol:
    // Send "CONNECT <port>\n", expect "OK <port>\n"
    _, err = fmt.Fprintf(conn, "CONNECT %d\n", port)
    if err != nil {
        conn.Close()
        return nil, err
    }
    reader := bufio.NewReader(conn)
    response, err := reader.ReadString('\n')
    if err != nil {
        conn.Close()
        return nil, err
    }
    if !strings.HasPrefix(response, "OK") {
        conn.Close()
        return nil, fmt.Errorf("vsock connect rejected: %s", response)
    }
    return conn, nil
}
```

### 4.4 Cleanup

The `Stop()` method and a deferred cleanup function must remove:
- API socket UDS file
- vsock UDS file
- Per-port listener UDS files (`{vsockPath}_{port}`)
- Temp directory

Register cleanup via `runtime.SetFinalizer` as a safety net, but primary cleanup is explicit in `Stop()`.

---

## 5. Virtualization.framework Backend (macOS)

### 5.1 Dependencies

- `github.com/Code-Hex/vz/v3` (cgo, links Objective-C Virtualization.framework)
- macOS 12+ (Big Sur or later)
- Binary must be codesigned with `com.apple.security.virtualization` entitlement
- `CGO_ENABLED=1` for host binary build

### 5.2 VM Lifecycle

```go
// internal/hypervisor/vf/vm.go
//go:build darwin

package vf

type VzVM struct {
    cfg          hypervisor.Config
    machine      *vz.VirtualMachine
    vsockDevice  *vz.VirtioSocketDevice
    vsockConfig  *vz.VirtioSocketDeviceConfiguration
    listeners    map[uint32]*vz.VirtioSocketListener
    mu           sync.Mutex
}

func New(cfg hypervisor.Config) (*VzVM, error) {
    // Validate: macOS version, entitlements
}
```

**Start flow:**
1. Create `vz.LinuxBootLoader` with kernel path (+ optional initrd)
2. Build `vz.VirtualMachineConfiguration`:
   - `NewVirtualMachineConfiguration(bootLoader, vcpus, memoryBytes)`
   - Map `RootDrive` + `ExtraDrives` → `[]vz.StorageDeviceConfiguration` via `VirtioBlockDeviceConfiguration`
   - One `VirtioSocketDeviceConfiguration` (only one allowed per VM)
   - `VirtioEntropyDeviceConfiguration` (for /dev/urandom in guest)
   - No network devices
3. `Validate()` the config
4. `vz.NewVirtualMachine(config)`
5. Start the machine, get vsock device via `machine.SocketDevices()[0]`
6. Wait for guest agent readiness on vsock port 1000

**Stop flow:**
1. `machine.RequestStop()` (ACPI power button)
2. If context deadline exceeded, `machine.Stop()` (force)
3. No temp files to clean up (Vz manages its own resources)

### 5.3 vsock Implementation

The Vz API provides vsock directly through the `VirtioSocketDevice`, returning `net.Conn`-compatible connections. No UDS intermediary.

```go
// internal/hypervisor/vf/vsock.go
//go:build darwin

package vf

// vzListener wraps VirtioSocketDevice listening into net.Listener.
type vzListener struct {
    device   *vz.VirtioSocketDevice
    port     uint32
    connCh   chan *vz.VirtioSocketConnection
    done     chan struct{}
    listener *vz.VirtioSocketListener
}

func (l *vzListener) Accept() (net.Conn, error) {
    select {
    case conn := <-l.connCh:
        return conn, nil
    case <-l.done:
        return nil, net.ErrClosed
    }
}

func (l *vzListener) Close() error {
    close(l.done)
    l.device.RemoveSocketListenerForPort(l.port)
    return nil
}

func (l *vzListener) Addr() net.Addr {
    return vsockAddr{port: l.port}
}

// VSockListen sets up a listener on the VirtioSocketDevice for the given port.
// The Vz framework calls back when guest connects; we channel those into Accept().
func (vm *VzVM) VSockListen(port uint32) (net.Listener, error) {
    ln := &vzListener{
        device: vm.vsockDevice,
        port:   port,
        connCh: make(chan *vz.VirtioSocketConnection, 16),
        done:   make(chan struct{}),
    }

    listener, err := vz.NewVirtioSocketListener(func(conn *vz.VirtioSocketConnection, err error) {
        if err != nil {
            return
        }
        select {
        case ln.connCh <- conn:
        case <-ln.done:
            conn.Close()
        }
    })
    if err != nil {
        return nil, err
    }

    ln.listener = listener
    vm.vsockDevice.SetSocketListenerForPort(listener, port)

    vm.mu.Lock()
    vm.listeners[port] = listener
    vm.mu.Unlock()

    return ln, nil
}

// VSockConnect initiates a host→guest connection on the given port.
// Wraps the async callback API into a synchronous call.
func (vm *VzVM) VSockConnect(port uint32) (net.Conn, error) {
    ch := make(chan connectResult, 1)
    vm.vsockDevice.ConnectToPort(port, func(conn *vz.VirtioSocketConnection, err error) {
        ch <- connectResult{conn: conn, err: err}
    })

    result := <-ch
    if result.err != nil {
        return nil, fmt.Errorf("vsock connect port %d: %w", port, result.err)
    }
    return result.conn, nil
}

type connectResult struct {
    conn *vz.VirtioSocketConnection
    err  error
}

// vsockAddr implements net.Addr for vsock.
type vsockAddr struct {
    port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("vsock://:%d", a.port) }
```

### 5.4 Entitlements Check

Provide a helper that checks whether the running binary has the required entitlement, and gives a clear error message if not:

```go
// internal/hypervisor/vf/entitlements.go
//go:build darwin

package vf

import (
    "fmt"
    "os"
    "os/exec"
)

// CheckEntitlements verifies the binary is codesigned with the
// virtualization entitlement. Called early in New() to fail fast
// with a helpful error message.
func CheckEntitlements() error {
    exe, err := os.Executable()
    if err != nil {
        return err
    }
    out, err := exec.Command("codesign", "-d", "--entitlements", ":-", exe).CombinedOutput()
    if err != nil {
        return fmt.Errorf(
            "keel binary is not codesigned. Run:\n"+
                "  codesign --entitlements keel.entitlements --force -s - %s\n"+
                "Error: %w", exe, err)
    }
    if !strings.Contains(string(out), "com.apple.security.virtualization") {
        return fmt.Errorf(
            "keel binary is missing the virtualization entitlement. Run:\n"+
                "  codesign --entitlements keel.entitlements --force -s - %s", exe)
    }
    return nil
}
```

### 5.5 Drive Configuration

```go
// Map hypervisor.DriveConfig to Vz block device
func createDrive(d hypervisor.DriveConfig) (vz.StorageDeviceConfiguration, error) {
    attachment, err := vz.NewDiskImageStorageDeviceAttachment(d.Path, d.ReadOnly)
    if err != nil {
        return nil, fmt.Errorf("drive %s: %w", d.ID, err)
    }
    config, err := vz.NewVirtioBlockDeviceConfiguration(attachment)
    if err != nil {
        return nil, err
    }
    // Set block device identifier so guest can identify drives
    // (e.g., "rootfs", "workspace")
    if err := config.SetBlockDeviceIdentifier(d.ID); err != nil {
        // Identifier support requires macOS 12.3+, non-fatal
    }
    return config, nil
}
```

---

## 6. Consuming the Abstraction

All code above the hypervisor layer uses the interface. Examples of how each subsystem integrates:

```go
// internal/pty/host.go — PTY handler (platform-agnostic)
func RunPTY(vm hypervisor.VM, command string) (int, error) {
    conn, err := vm.VSockConnect(1000)  // ← only touch point
    if err != nil {
        return -1, err
    }
    defer conn.Close()
    // ... PTY framing protocol over conn (net.Conn)
}
```

```go
// internal/network/dns.go — DNS policy proxy (platform-agnostic)
func ServeDNSPolicy(vm hypervisor.VM, policy *Policy) error {
    ln, err := vm.VSockListen(3053)  // ← only touch point
    if err != nil {
        return err
    }
    defer ln.Close()
    for {
        conn, err := ln.Accept()  // net.Conn from either FC or Vz
        if err != nil {
            return err
        }
        go handleDNS(conn, policy)
    }
}
```

```go
// internal/network/tcp.go — TCP policy proxy (platform-agnostic)
func ServeTCPPolicy(vm hypervisor.VM, policy *Policy) error {
    ln, err := vm.VSockListen(3128)  // ← only touch point
    if err != nil {
        return err
    }
    defer ln.Close()
    for {
        conn, err := ln.Accept()
        if err != nil {
            return err
        }
        go handleTCP(conn, policy)
    }
}
```

```go
// internal/cli/run.go — orchestration (platform-agnostic)
func runCommand(cfg *config.Config, args []string) error {
    vmCfg := hypervisor.Config{ /* from cfg */ }
    vm, err := hypervisor.New(vmCfg)  // dispatches to FC or Vz
    if err != nil {
        return err
    }

    // Start vsock listeners before booting (so they're ready when guest connects)
    dnsLn, _ := vm.VSockListen(3053)
    tcpLn, _ := vm.VSockListen(3128)

    go ServeDNSPolicy(dnsLn, policy)
    go ServeTCPPolicy(tcpLn, policy)

    if err := vm.Start(ctx); err != nil {
        return err
    }
    defer vm.Stop(ctx)

    exitCode, err := RunPTY(vm, shellCommand(args))
    os.Exit(exitCode)
}
```

---

## 7. Testing Strategy

### 7.1 Unit Tests (No VM, Both Platforms)

Test each backend's configuration building and validation logic without actually booting a VM:

```go
// internal/hypervisor/firecracker/vm_test.go
//go:build linux

func TestFirecrackerConfigMapping(t *testing.T) {
    cfg := hypervisor.Config{VCPUs: 2, MemoryMB: 2048, ...}
    fcCfg, err := buildFirecrackerConfig(cfg)
    require.NoError(t, err)
    assert.Equal(t, int64(2), *fcCfg.MachineCfg.VcpuCount)
    assert.Len(t, fcCfg.VsockDevices, 1)
    assert.Empty(t, fcCfg.NetworkInterfaces)
}
```

```go
// internal/hypervisor/vf/vm_test.go
//go:build darwin

func TestVzConfigMapping(t *testing.T) {
    cfg := hypervisor.Config{VCPUs: 2, MemoryMB: 2048, ...}
    vzCfg, err := buildVzConfig(cfg)
    require.NoError(t, err)
    // Validate drive count, vsock device present, no network devices
}

func TestEntitlementsCheck(t *testing.T) {
    // Test that CheckEntitlements returns a helpful error
    // when binary is not signed (likely the case in `go test`)
    err := CheckEntitlements()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "codesign")
}
```

### 7.2 Interface Compliance Test

A shared test that both backends must pass, run only during integration:

```go
// internal/hypervisor/conformance_test.go
//go:build integration

func TestVMConformance(t *testing.T) {
    cfg := testConfig(t) // loads test kernel + minimal rootfs
    vm, err := hypervisor.New(cfg)
    require.NoError(t, err)

    // Listener must work before Start
    ln, err := vm.VSockListen(1000)
    require.NoError(t, err)
    defer ln.Close()

    // Start must succeed
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    require.NoError(t, vm.Start(ctx))
    defer vm.Stop(ctx)

    // Accept must return a net.Conn when guest agent connects
    conn, err := ln.Accept()
    require.NoError(t, err)
    defer conn.Close()

    // Read/Write must work
    _, err = conn.Write([]byte("ping"))
    require.NoError(t, err)

    buf := make([]byte, 4)
    _, err = io.ReadFull(conn, buf)
    require.NoError(t, err)
    assert.Equal(t, "pong", string(buf))

    // VSockConnect must work after Start
    conn2, err := vm.VSockConnect(1000)
    require.NoError(t, err)
    conn2.Close()

    // Stop must be graceful
    stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer stopCancel()
    require.NoError(t, vm.Stop(stopCtx))
}
```

### 7.3 CI Matrix

```yaml
# Unit tests (no VM) — runs on every push
test-hypervisor-linux:
  runs-on: ubuntu-latest
  run: go test ./internal/hypervisor/firecracker/... -short

test-hypervisor-macos:
  runs-on: macos-latest
  run: go test ./internal/hypervisor/vf/... -short

# Integration (VM required) — runs on main + PRs
integration-linux:
  runs-on: ubuntu-latest  # needs KVM
  run: go test ./internal/hypervisor/... -tags integration -v

integration-macos:
  runs-on: macos-latest   # Apple Silicon, supports Vz
  # Must codesign test binary before running
  run: |
    go test -c -o hypervisor.test ./internal/hypervisor/...  -tags integration
    codesign --entitlements hack/entitlements/keel.entitlements --force -s - hypervisor.test
    ./hypervisor.test -test.v -test.timeout 10m
```

**Important macOS CI detail:** `go test` compiles and runs a test binary. That binary needs the virtualization entitlement. So the integration test must be compiled first (`go test -c`), codesigned, then executed manually. This is the standard pattern for testing Virtualization.framework code in CI.

---

## 8. Platform Differences Cheat Sheet

| Aspect | Firecracker | Virtualization.framework |
|---|---|---|
| `New()` creates | `firecracker.Machine` via SDK | `vz.VirtualMachine` via cgo |
| `Start()` | `machine.Start(ctx)` | `machine.Start()` (async, poll state) |
| `Stop()` | `machine.Shutdown()` / `StopVMM()` | `machine.RequestStop()` / `Stop()` |
| `VSockListen()` | `net.Listen("unix", path_{port})` | `VirtioSocketDevice.SetSocketListenerForPort()` |
| `VSockConnect()` | UDS connect + `CONNECT {port}\n` | `VirtioSocketDevice.ConnectToPort()` callback |
| Connection type | `net.Conn` (from UDS) | `*vz.VirtioSocketConnection` (implements `net.Conn`) |
| Boot config | `firecracker.Config` struct | `vz.VirtualMachineConfiguration` |
| Kernel format | Raw vmlinux (x86_64) | Raw vmlinux via `LinuxBootLoader` (arm64 or x86_64) |
| Cleanup | Remove temp UDS files | None (framework manages) |
| Cgo | No | Yes |
| Entitlements | No | `com.apple.security.virtualization` |

---

## 9. Implementation Order

1. **`hypervisor.go`** — define interface, `Config`, `GuestArch()`
2. **Firecracker backend** — `vm.go` + `vsock.go` (you likely have most of this already)
3. **Vz backend** — `vm.go` + `vsock.go` + `entitlements.go`
4. **Build-tag dispatch** — `new_linux.go` + `new_darwin.go`
5. **Conformance test** — shared test both backends must pass
6. **CI workflows** — macOS integration with codesigned test binary
7. **Refactor consumers** — update PTY, network, CLI to use `hypervisor.VM` interface instead of direct Firecracker calls

Step 7 is where you verify the abstraction works end-to-end: if the PTY handler, DNS proxy, and TCP proxy all compile and pass tests on both platforms without any `//go:build` tags, the abstraction is correct.
