module github.com/moolen/keel/guest

go 1.25.0

require (
	github.com/creack/pty v1.1.24
	github.com/google/nftables v0.3.0
	github.com/mdlayher/vsock v1.2.1
	github.com/moolen/keel v0.0.0
	golang.org/x/sys v0.43.0
)

require (
	github.com/cilium/ebpf v0.21.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
)

replace github.com/moolen/keel => ..
