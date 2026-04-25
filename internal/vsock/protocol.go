package vsock

const (
	MessageData   byte = 0x01
	MessageResize byte = 0x02
	MessageExit   byte = 0x03
	MessageSignal byte = 0x04
)

const (
	PortPTY = 1000
	PortTCP = 3128
	PortDNS = 3053
)
