package inspector

import "testing"

func TestIsBitTorrentHandshake(t *testing.T) {
	t.Parallel()

	payload := []byte("\x13BitTorrent protocol")
	if !IsBitTorrentHandshake(payload) {
		t.Fatal("expected bittorrent signature to be detected")
	}
}

func TestIsBitTorrentHandshakeNegative(t *testing.T) {
	t.Parallel()

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if IsBitTorrentHandshake(payload) {
		t.Fatal("expected non-bittorrent payload to be ignored")
	}
}
