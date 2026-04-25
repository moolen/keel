package network

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func ParseClientHelloSNI(data []byte) (string, error) {
	if len(data) < 5 || data[0] != 0x16 {
		return "", errors.New("not a tls handshake record")
	}
	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+recordLength > len(data) {
		return "", errors.New("truncated tls record")
	}

	offset := 5
	if data[offset] != 0x01 {
		return "", errors.New("not a client hello")
	}
	handshakeLength := int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4
	if offset+handshakeLength > len(data) {
		return "", errors.New("truncated client hello")
	}

	offset += 2 + 32
	if offset >= len(data) {
		return "", errors.New("missing session id")
	}
	sessionIDLength := int(data[offset])
	offset++
	offset += sessionIDLength

	if offset+2 > len(data) {
		return "", errors.New("missing cipher suites")
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherSuitesLength

	if offset >= len(data) {
		return "", errors.New("missing compression methods")
	}
	compressionMethodsLength := int(data[offset])
	offset++
	offset += compressionMethodsLength

	if offset+2 > len(data) {
		return "", errors.New("missing extensions")
	}
	extensionsLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	end := offset + extensionsLength
	if end > len(data) {
		return "", errors.New("truncated extensions")
	}

	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if offset+extLength > end {
			return "", errors.New("truncated extension payload")
		}
		if extType == 0x0000 {
			return parseServerNameExtension(data[offset : offset+extLength])
		}
		offset += extLength
	}

	return "", errors.New("sni extension not present")
}

func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("invalid server name extension")
	}
	listLength := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLength > len(data) {
		return "", errors.New("truncated server name list")
	}

	offset := 2
	for offset+3 <= len(data) {
		nameType := data[offset]
		nameLength := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3
		if offset+nameLength > len(data) {
			return "", fmt.Errorf("truncated server name entry")
		}
		if nameType == 0 {
			return string(data[offset : offset+nameLength]), nil
		}
		offset += nameLength
	}
	return "", errors.New("host_name entry not present")
}
