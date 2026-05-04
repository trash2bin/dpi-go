package inspector

import (
	"encoding/binary"
)

const (
	tlsRecordTypeHandshake = 0x16
	tlsHandshakeTypeClient = 0x01
	tlsExtensionServerName = 0x0000
	tlsNameTypeHostName    = 0x00
)

// ExtractTLSSNI parses TLS ClientHello payload and returns SNI host when present.
func ExtractTLSSNI(payload []byte) (string, bool) {
	if len(payload) < 5 {
		return "", false
	}

	if payload[0] != tlsRecordTypeHandshake {
		return "", false
	}
	if payload[1] != 0x03 {
		return "", false
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen <= 0 || len(payload) < 5+recordLen {
		return "", false
	}
	record := payload[5 : 5+recordLen]

	if len(record) < 4 || record[0] != tlsHandshakeTypeClient {
		return "", false
	}

	handshakeLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if handshakeLen <= 0 || len(record) < 4+handshakeLen {
		return "", false
	}
	clientHello := record[4 : 4+handshakeLen]

	cursor := 0
	if len(clientHello) < 2+32+1 {
		return "", false
	}

	cursor += 2  // legacy_version
	cursor += 32 // random

	sessionIDLen := int(clientHello[cursor])
	cursor++
	if len(clientHello) < cursor+sessionIDLen+2 {
		return "", false
	}
	cursor += sessionIDLen

	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHello[cursor : cursor+2]))
	cursor += 2
	if cipherSuitesLen < 2 || len(clientHello) < cursor+cipherSuitesLen+1 {
		return "", false
	}
	cursor += cipherSuitesLen

	compressionMethodsLen := int(clientHello[cursor])
	cursor++
	if len(clientHello) < cursor+compressionMethodsLen+2 {
		return "", false
	}
	cursor += compressionMethodsLen

	extensionsLen := int(binary.BigEndian.Uint16(clientHello[cursor : cursor+2]))
	cursor += 2
	if len(clientHello) < cursor+extensionsLen {
		return "", false
	}
	extensions := clientHello[cursor : cursor+extensionsLen]

	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[0:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			return "", false
		}

		extData := extensions[:extLen]
		extensions = extensions[extLen:]

		if extType != tlsExtensionServerName {
			continue
		}

		host, ok := parseSNIExtension(extData)
		if !ok {
			return "", false
		}
		return host, true
	}

	return "", false
}

func parseSNIExtension(extData []byte) (string, bool) {
	if len(extData) < 2 {
		return "", false
	}

	listLen := int(binary.BigEndian.Uint16(extData[0:2]))
	if listLen <= 0 || len(extData) < 2+listLen {
		return "", false
	}

	names := extData[2 : 2+listLen]
	for len(names) >= 3 {
		nameType := names[0]
		nameLen := int(binary.BigEndian.Uint16(names[1:3]))
		names = names[3:]
		if len(names) < nameLen {
			return "", false
		}
		nameBytes := names[:nameLen]
		names = names[nameLen:]

		if nameType != tlsNameTypeHostName {
			continue
		}

		host := normalizeHost(string(nameBytes))
		if host == "" {
			return "", false
		}
		return host, true
	}

	return "", false
}
