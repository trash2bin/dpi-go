package inspector

import "testing"

// buildOpenVPNUDP собирает минимальный валидный UDP-пакет OpenVPN
// Структура: [1 байт opcode+keyid] [8 байт session_id] [4 байта packet_id]
func buildOpenVPNUDP(opcode uint8) []byte {
	return []byte{
		opcode << 3,                                    // opcode (старшие 5 бит), key_id=0
		0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, // session_id (8 байт, ненулевой)
		0x00, 0x00, 0x00, 0x01, // packet_id
	}
}

// buildOpenVPNTCP собирает минимальный валидный TCP-пакет OpenVPN
// Структура: [2 байта length big-endian] [1 байт opcode+keyid] [8 байт session_id] [4 байта packet_id]
func buildOpenVPNTCP(opcode uint8) []byte {
	body := buildOpenVPNUDP(opcode)
	length := len(body)
	return append([]byte{byte(length >> 8), byte(length)}, body...)
}

// --- Позитивные тесты ---

func TestIsOpenVPN_UDP_HardResetClientV2(t *testing.T) {
	t.Parallel()

	// Опкод 7 — самый типичный первый пакет клиента (P_CONTROL_HARD_RESET_CLIENT_V2)
	payload := buildOpenVPNUDP(7)
	if !IsOpenVPN(payload, false) {
		t.Fatalf("expected OpenVPN UDP detected, first byte=0x%02X", payload[0])
	}
}

func TestIsOpenVPN_TCP_HardResetClientV2(t *testing.T) {
	t.Parallel()

	payload := buildOpenVPNTCP(7)
	if !IsOpenVPN(payload, true) {
		t.Fatalf("expected OpenVPN TCP detected, first byte=0x%02X", payload[0])
	}
}

func TestIsOpenVPN_UDP_AllControlOpcodes(t *testing.T) {
	t.Parallel()

	// Все контрольные опкоды (кроме DATA 6 и 9 они намеренно не детектируются без контекста)
	controlOpcodes := []struct {
		code uint8
		name string
	}{
		{1, "P_CONTROL_HARD_RESET_CLIENT_V1"},
		{2, "P_CONTROL_HARD_RESET_SERVER_V1"},
		{3, "P_CONTROL_SOFT_RESET_V1"},
		{4, "P_CONTROL_V1"},
		{5, "P_ACK_V1"},
		{7, "P_CONTROL_HARD_RESET_CLIENT_V2"},
		{8, "P_CONTROL_HARD_RESET_SERVER_V2"},
	}

	for _, tc := range controlOpcodes {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload := buildOpenVPNUDP(tc.code)
			if !IsOpenVPN(payload, false) {
				t.Errorf("opcode %d (%s): expected detection, first byte=0x%02X", tc.code, tc.name, payload[0])
			}
		})
	}
}

// --- Негативные тесты ---

func TestIsOpenVPN_Negative_HTTP(t *testing.T) {
	t.Parallel()

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if IsOpenVPN(payload, true) {
		t.Fatal("HTTP payload must not be detected as OpenVPN")
	}
	if IsOpenVPN(payload, false) {
		t.Fatal("HTTP payload must not be detected as OpenVPN (UDP path)")
	}
}

func TestIsOpenVPN_Negative_BitTorrent(t *testing.T) {
	t.Parallel()

	payload := []byte("\x13BitTorrent protocol")
	if IsOpenVPN(payload, true) {
		t.Fatal("BitTorrent payload must not be detected as OpenVPN")
	}
}

func TestIsOpenVPN_Negative_TooShort(t *testing.T) {
	t.Parallel()

	cases := [][]byte{
		{},           // пустой
		{0x38},       // только опкод
		{0x38, 0x01}, // опкод + 1 байт сессии (мало)
	}
	for _, payload := range cases {
		if IsOpenVPN(payload, false) {
			t.Fatalf("too-short payload (len=%d) must not be detected", len(payload))
		}
		if IsOpenVPN(payload, true) {
			t.Fatalf("too-short payload (len=%d) must not be detected (TCP)", len(payload))
		}
	}
}

func TestIsOpenVPN_Negative_ZeroSessionID(t *testing.T) {
	t.Parallel()

	// Нулевой session_id невалидный пакет
	payload := []byte{
		0x38,                                           // opcode=7
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // session_id = все нули
		0x00, 0x00, 0x00, 0x01,
	}
	if IsOpenVPN(payload, false) {
		t.Fatal("zero session_id must not be detected as OpenVPN")
	}
}

func TestIsOpenVPN_Negative_InvalidOpcode(t *testing.T) {
	t.Parallel()

	// Опкод 15 — не существует в спецификации OpenVPN
	payload := buildOpenVPNUDP(15)
	if IsOpenVPN(payload, false) {
		t.Fatal("invalid opcode must not be detected as OpenVPN")
	}
}

func TestIsOpenVPN_Negative_DataPacketsIgnored(t *testing.T) {
	t.Parallel()

	// DATA-пакеты (опкоды 6 и 9) намеренно не детектируются без контекста сессии
	for _, opcode := range []uint8{6, 9} {
		payload := buildOpenVPNUDP(opcode)
		if IsOpenVPN(payload, false) {
			t.Fatalf("DATA opcode %d should not be detected without session context", opcode)
		}
	}
}
