//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"dpi-kyrsach/internal/inspector"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestInspectorPCAPBlockedScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ins := inspector.New(inspector.Config{
		FailOpen:       true,
		BlockedDomains: []string{"blocked.example", "rutracker.org"},
		Mode:           "skeleton",
	}, nil)

	cases := []struct {
		name        string
		fixture     string
		wantVerdict inspector.Verdict
		wantReason  string
	}{
		{
			name:        "HTTP Host blocked from PCAP",
			fixture:     "http_blocked.pcap",
			wantVerdict: inspector.VerdictDrop,
			wantReason:  "http_host_blocked",
		},
		{
			name:        "TLS SNI blocked from PCAP",
			fixture:     "tls_blocked.pcap",
			wantVerdict: inspector.VerdictDrop,
			wantReason:  "tls_sni_blocked",
		},
		{
			name:        "BitTorrent blocked from PCAP",
			fixture:     "bittorrent.pcap",
			wantVerdict: inspector.VerdictDrop,
			wantReason:  "bittorrent_signature",
		},
		{
			name:        "OpenVPN blocked from PCAP",
			fixture:     "openvpn.pcap",
			wantVerdict: inspector.VerdictDrop,
			wantReason:  "openvpn_signature",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			packet := readFirstPacketFromFixture(t, tc.fixture)
			decision := ins.AnalyzePacket(packet)
			if decision.Verdict != tc.wantVerdict {
				t.Fatalf("unexpected verdict: got=%s want=%s reason=%s", decision.Verdict, tc.wantVerdict, decision.Reason)
			}
			if decision.Reason != tc.wantReason {
				t.Fatalf("unexpected reason: got=%s want=%s", decision.Reason, tc.wantReason)
			}
		})
	}
}

func readFirstPacketFromFixture(t *testing.T, fixture string) []byte {
	t.Helper()

	path := filepath.Join("..", "pcap", fixture)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture %s: %v", path, err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("open pcap reader for %s: %v", path, err)
	}

	data, _, err := r.ZeroCopyReadPacketData()
	if err != nil {
		t.Fatalf("read first packet from %s: %v", path, err)
	}

	// Проверяем, есть ли Ethernet-заголовок.
	// Обычно в pcap файлах LinkType == 1 (Ethernet).
	// Ethernet заголовок имеет длину 14 байт.
	// После него идет IP-заголовок.
	// Первый байт IP-заголовка IPv4 обычно 0x45 (Version 4, IHL 5).
	// Первый байт IPv6 обычно 0x60.
	linkType := r.LinkType()

	var ipPacket []byte

	if linkType == layers.LinkTypeEthernet {
		// Отрезаем 14 байт Ethernet-заголовка
		if len(data) < 14 {
			t.Fatalf("packet too short for Ethernet header")
		}
		ipPacket = data[14:]
	} else if linkType == layers.LinkTypeRaw || linkType == layers.LinkTypeIPv4 {
		// Если pcap уже содержит чистые IP-пакеты
		ipPacket = data
	} else {
		t.Fatalf("unsupported link type: %v", linkType)
	}

	return append([]byte(nil), ipPacket...)
}

func TestPCAPFixturesContainPackets(t *testing.T) {
	fixtures := []string{"http_blocked.pcap", "tls_blocked.pcap", "bittorrent.pcap", "openvpn.pcap"}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			path := filepath.Join("..", "pcap", fixture)
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open fixture %s: %v", path, err)
			}
			defer f.Close()

			r, err := pcapgo.NewReader(f)
			if err != nil {
				t.Fatalf("pcap reader for %s: %v", path, err)
			}

			count := 0
			for {
				_, _, err = r.ZeroCopyReadPacketData()
				if err != nil {
					break
				}
				count++
			}
			if count == 0 {
				t.Fatalf("fixture %s has no packets", path)
			}
		})
	}
}
