package inspector

import (
	"context"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type fakeQueueRuntime struct {
	packets  []testPacket
	verdicts map[uint32]Verdict
}

type testPacket struct {
	id      uint32
	payload []byte
}

func (f *fakeQueueRuntime) Run(_ context.Context, _ uint16, decide func(packetID uint32, packet []byte) Verdict) error {
	if f.verdicts == nil {
		f.verdicts = make(map[uint32]Verdict)
	}
	for _, packet := range f.packets {
		f.verdicts[packet.id] = decide(packet.id, packet.payload)
	}
	return nil
}

func TestAnalyzePacketDropsBlockedHTTPHost(t *testing.T) {
	t.Parallel()

	ins := New(Config{FailOpen: true, BlockedDomains: []string{"blocked.example"}}, nil)
	packet := buildIPv4TCPPacket(t, []byte("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n"))

	decision := ins.AnalyzePacket(packet)
	if decision.Verdict != VerdictDrop {
		t.Fatalf("expected drop verdict, got %s (%s)", decision.Verdict, decision.Reason)
	}
}

func TestAnalyzePacketDropsBlockedHTTPSubdomain(t *testing.T) {
	t.Parallel()

	ins := New(Config{FailOpen: true, BlockedDomains: []string{"blocked.example"}}, nil)
	packet := buildIPv4TCPPacket(t, []byte("GET / HTTP/1.1\r\nHost: cdn.blocked.example\r\n\r\n"))

	decision := ins.AnalyzePacket(packet)
	if decision.Verdict != VerdictDrop {
		t.Fatalf("expected drop verdict for blocked subdomain, got %s (%s)", decision.Verdict, decision.Reason)
	}
}

func TestAnalyzePacketDropsBitTorrent(t *testing.T) {
	t.Parallel()

	ins := New(Config{FailOpen: true}, nil)
	packet := buildIPv4TCPPacket(t, []byte("\x13BitTorrent protocol"))

	decision := ins.AnalyzePacket(packet)
	if decision.Verdict != VerdictDrop {
		t.Fatalf("expected drop verdict, got %s (%s)", decision.Verdict, decision.Reason)
	}
}

func TestAnalyzePacketDropsBlockedTLSSNI(t *testing.T) {
	t.Parallel()

	ins := New(Config{FailOpen: true, BlockedDomains: []string{"blocked.example"}}, nil)
	packet := buildIPv4TCPPacket(t, buildTLSClientHelloWithSNI(t, "blocked.example"))

	decision := ins.AnalyzePacket(packet)
	if decision.Verdict != VerdictDrop {
		t.Fatalf("expected drop verdict, got %s (%s)", decision.Verdict, decision.Reason)
	}
	if decision.Reason != "tls_sni_blocked" {
		t.Fatalf("expected tls_sni_blocked reason, got %q", decision.Reason)
	}
}

func TestAnalyzePacketDropsBlockedTLSSNISubdomain(t *testing.T) {
	t.Parallel()

	ins := New(Config{FailOpen: true, BlockedDomains: []string{"blocked.example"}}, nil)
	packet := buildIPv4TCPPacket(t, buildTLSClientHelloWithSNI(t, "api.blocked.example"))

	decision := ins.AnalyzePacket(packet)
	if decision.Verdict != VerdictDrop {
		t.Fatalf("expected drop verdict for blocked SNI subdomain, got %s (%s)", decision.Verdict, decision.Reason)
	}
}

func TestAnalyzePacketAcceptsUnblockedHTTPHost(t *testing.T) {
	t.Parallel()

	ins := New(Config{FailOpen: true, BlockedDomains: []string{"blocked.example"}}, nil)
	packet := buildIPv4TCPPacket(t, []byte("GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n"))

	decision := ins.AnalyzePacket(packet)
	if decision.Verdict != VerdictAccept {
		t.Fatalf("expected accept verdict, got %s (%s)", decision.Verdict, decision.Reason)
	}
}

func TestAnalyzePacketFailOpenAndFailClosed(t *testing.T) {
	t.Parallel()

	garbage := []byte("not an ip packet")

	insFailOpen := New(Config{FailOpen: true}, nil)
	if got := insFailOpen.AnalyzePacket(garbage).Verdict; got != VerdictAccept {
		t.Fatalf("expected fail-open accept, got %s", got)
	}

	insFailClosed := New(Config{FailOpen: false}, nil)
	if got := insFailClosed.AnalyzePacket(garbage).Verdict; got != VerdictDrop {
		t.Fatalf("expected fail-closed drop, got %s", got)
	}
}

func TestRunUsesQueueRuntimeVerdicts(t *testing.T) {
	t.Parallel()

	queue := &fakeQueueRuntime{
		packets: []testPacket{{
			id:      77,
			payload: buildIPv4TCPPacket(t, []byte("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")),
		}},
	}
	ins := newWithRuntime(Config{FailOpen: true, BlockedDomains: []string{"blocked.example"}}, nil, queue)

	if err := ins.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if queue.verdicts[77] != VerdictDrop {
		t.Fatalf("expected runtime verdict drop, got %s", queue.verdicts[77])
	}
}

func buildIPv4TCPPacket(t *testing.T, appPayload []byte) []byte {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{10, 0, 0, 10},
		DstIP:    []byte{93, 184, 216, 34},
	}
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 80,
		SYN:     true,
		PSH:     true,
		ACK:     true,
		Seq:     100,
		Ack:     200,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum() error = %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(appPayload)); err != nil {
		t.Fatalf("SerializeLayers() error = %v", err)
	}
	return buf.Bytes()
}
