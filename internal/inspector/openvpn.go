package inspector

// Валидные опкоды OpenVPN (значения после >> 3)
const (
	P_CONTROL_HARD_RESET_CLIENT_V1 = 1
	P_CONTROL_HARD_RESET_SERVER_V1 = 2
	P_CONTROL_SOFT_RESET_V1        = 3
	P_CONTROL_V1                   = 4
	P_ACK_V1                       = 5
	P_DATA_V1                      = 6
	P_CONTROL_HARD_RESET_CLIENT_V2 = 7
	P_CONTROL_HARD_RESET_SERVER_V2 = 8
	P_DATA_V2                      = 9
)

var validOpcodes = map[uint8]bool{
	P_CONTROL_HARD_RESET_CLIENT_V1: true,
	P_CONTROL_HARD_RESET_SERVER_V1: true,
	P_CONTROL_SOFT_RESET_V1:        true,
	P_CONTROL_V1:                   true,
	P_ACK_V1:                       true,
	P_DATA_V1:                      true,
	P_CONTROL_HARD_RESET_CLIENT_V2: true,
	P_CONTROL_HARD_RESET_SERVER_V2: true,
	P_DATA_V2:                      true,
}

// IsOpenVPNUDP — детектор для UDP-пакетов
//
// Структура UDP-пакета OpenVPN:
//
//	Минимум: 1 (opcode) + 8 (session_id) + 4 (packet_id) = 13 байт
func IsOpenVPNUDP(data []byte) bool {
	if len(data) < 13 {
		return false
	}

	firstByte := data[0]
	opcode := firstByte >> 3
	keyID := firstByte & 0x07

	// 1. Валидный контрольный опкод
	if !validOpcodes[opcode] {
		return false
	}

	// 2. DATA-пакеты не детектируем без контекста сессии
	if opcode == P_DATA_V1 || opcode == P_DATA_V2 {
		return false
	}

	// 3. key_id может быть 0..7 (0 для handshake, 1-7 для rekey/mid-session)
	// Для stateless DPI допускаем все, но отсеиваем мусор ниже.
	_ = keyID

	sessionID := data[1:9]

	// 4. Session ID не должен быть нулевым
	if allZeros(sessionID) {
		return false
	}

	// 5. Эвристика против текстовых протоколов (HTTP, SMTP, XMPP и т.д.)
	// Session ID в OpenVPN — криптографически случайные бинарные данные.
	// Если все 8 байт печатаемые ASCII, это почти наверняка текст.
	if isPrintableASCII(sessionID) {
		return false
	}

	// 6. Эвристика против TLS ClientHello (0x16 0x03 0x01/0x03 ...)
	// TLS Handshake часто маппится на opcode=2. Отсекаем по сигнатуре версии.
	if data[0] == 0x16 && len(data) > 2 && data[1] == 0x03 {
		return false
	}

	return true
}

// isPrintableASCII возвращает true, если ВСЕ байты слайса печатаемые ASCII
func isPrintableASCII(b []byte) bool {
	for _, v := range b {
		if v < 0x20 || v > 0x7E {
			return false
		}
	}
	return true
}

// IsOpenVPNTCP — детектор для TCP-пакетов
//
// Структура TCP-пакета OpenVPN:
//
//	[2 байта: length (big-endian)] [1 байт: opcode+keyid] [8 байт: session_id] [...]
func IsOpenVPNTCP(data []byte) bool {
	// Минимум: 2 байта длины + 1 байт опкода + 8 байт session_id
	if len(data) < 11 {
		return false
	}

	// Читаем задекларированную длину пакета
	declaredLen := int(data[0])<<8 | int(data[1])

	// Длина должна совпадать с реальными данными после 2-байтного заголовка
	if declaredLen != len(data)-2 {
		return false
	}

	// Проверяем опкод (3-й байт, индекс 2)
	opcode := data[2] >> 3
	if !validOpcodes[opcode] {
		return false
	}

	if opcode == P_DATA_V1 || opcode == P_DATA_V2 {
		return false
	}

	// Проверяем session_id
	sessionID := data[3:11]
	if allZeros(sessionID) {
		return false
	}

	return true
}

// IsOpenVPN — авто-определение UDP vs TCP
func IsOpenVPN(data []byte, isTCP bool) bool {
	if isTCP {
		return IsOpenVPNTCP(data)
	}
	return IsOpenVPNUDP(data)
}

func allZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
