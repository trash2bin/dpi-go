package inspector

import (
	"encoding/binary"
	"testing"
)

func TestExtractTLSSNIFound(t *testing.T) {
	t.Parallel()

	payload := buildTLSClientHelloWithSNI(t, "RuTracker.Org")
	sni, ok := ExtractTLSSNI(payload)
	if !ok {
		t.Fatal("expected TLS SNI to be extracted")
	}
	if sni != "rutracker.org" {
		t.Fatalf("unexpected SNI value: %q", sni)
	}
}

func TestExtractTLSSNINotPresent(t *testing.T) {
	t.Parallel()

	payload := buildTLSClientHelloNoSNI(t)
	if _, ok := ExtractTLSSNI(payload); ok {
		t.Fatal("expected SNI extraction to fail when extension is missing")
	}
}

func TestExtractTLSSNIMalformed(t *testing.T) {
	t.Parallel()

	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x30, 0x01, 0x00}
	if _, ok := ExtractTLSSNI(payload); ok {
		t.Fatal("expected malformed TLS payload to be ignored")
	}
}

func buildTLSClientHelloWithSNI(t *testing.T, host string) []byte {
	t.Helper()

	hostBytes := []byte(host)
	nameEntry := make([]byte, 0, 3+len(hostBytes))
	nameEntry = append(nameEntry, tlsNameTypeHostName)
	nameEntry = binary.BigEndian.AppendUint16(nameEntry, uint16(len(hostBytes)))
	nameEntry = append(nameEntry, hostBytes...)

	sniData := make([]byte, 0, 2+len(nameEntry))
	sniData = binary.BigEndian.AppendUint16(sniData, uint16(len(nameEntry)))
	sniData = append(sniData, nameEntry...)

	ext := make([]byte, 0, 4+len(sniData))
	ext = binary.BigEndian.AppendUint16(ext, tlsExtensionServerName)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(sniData)))
	ext = append(ext, sniData...)

	return buildTLSClientHello(t, ext)
}

func buildTLSClientHelloNoSNI(t *testing.T) []byte {
	t.Helper()

	// supported_versions extension as a harmless non-SNI example
	extData := []byte{0x02, 0x03, 0x04}
	ext := make([]byte, 0, 4+len(extData))
	ext = binary.BigEndian.AppendUint16(ext, 0x002b)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(extData)))
	ext = append(ext, extData...)

	return buildTLSClientHello(t, ext)
}

func buildTLSClientHello(t *testing.T, extensions []byte) []byte {
	t.Helper()

	body := make([]byte, 0, 256)
	body = append(body, 0x03, 0x03) // legacy_version TLS1.2

	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	body = append(body, random...)

	body = append(body, 0x00)                   // session id len
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00)             // one compression method: null

	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, tlsHandshakeTypeClient)
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, tlsRecordTypeHandshake, 0x03, 0x01)
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)

	return record
}
