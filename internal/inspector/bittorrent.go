package inspector

import "bytes"

var bitTorrentHandshakeSignature = []byte("\x13BitTorrent protocol")

// IsBitTorrentHandshake returns true when payload contains a BitTorrent handshake signature.
func IsBitTorrentHandshake(payload []byte) bool {
	if len(payload) < len(bitTorrentHandshakeSignature) {
		return false
	}
	return bytes.Contains(payload, bitTorrentHandshakeSignature)
}
