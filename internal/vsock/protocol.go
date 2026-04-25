package vsock

import (
	"encoding/binary"
	"fmt"
	"io"
)

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

type Frame struct {
	Type   byte
	Data   []byte
	Rows   uint16
	Cols   uint16
	Code   byte
	Signal byte
}

func WriteDataFrame(w io.Writer, data []byte) error {
	if err := writeByte(w, MessageData); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func WriteResizeFrame(w io.Writer, rows, cols uint16) error {
	if err := writeByte(w, MessageResize); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, rows); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, cols)
}

func WriteExitFrame(w io.Writer, code byte) error {
	if err := writeByte(w, MessageExit); err != nil {
		return err
	}
	return writeByte(w, code)
}

func WriteSignalFrame(w io.Writer, signal byte) error {
	if err := writeByte(w, MessageSignal); err != nil {
		return err
	}
	return writeByte(w, signal)
}

func ReadFrame(r io.Reader) (Frame, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return Frame{}, err
	}

	frame := Frame{Type: typ[0]}
	switch typ[0] {
	case MessageData:
		var length uint32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return Frame{}, err
		}
		frame.Data = make([]byte, int(length))
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			return Frame{}, err
		}
	case MessageResize:
		if err := binary.Read(r, binary.BigEndian, &frame.Rows); err != nil {
			return Frame{}, err
		}
		if err := binary.Read(r, binary.BigEndian, &frame.Cols); err != nil {
			return Frame{}, err
		}
	case MessageExit:
		if err := readByte(r, &frame.Code); err != nil {
			return Frame{}, err
		}
	case MessageSignal:
		if err := readByte(r, &frame.Signal); err != nil {
			return Frame{}, err
		}
	default:
		return Frame{}, fmt.Errorf("unknown frame type %d", typ[0])
	}
	return frame, nil
}

func writeByte(w io.Writer, value byte) error {
	_, err := w.Write([]byte{value})
	return err
}

func readByte(r io.Reader, value *byte) error {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	*value = buf[0]
	return nil
}
