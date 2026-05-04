package inspector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Verdict is an NFQUEUE-like decision abstraction for packet processing.
type Verdict string

// To specify the payload and packet type
type transportPayload struct {
	data  []byte
	isTCP bool
}

const (
	VerdictAccept Verdict = "accept"
	VerdictDrop   Verdict = "drop"
)

// Decision describes packet handling result.
type Decision struct {
	Verdict Verdict
	Reason  string
}

// Config controls inspector behavior.
type Config struct {
	Enabled        bool
	QueueNum       uint16
	FailOpen       bool
	Mode           string
	BlockedDomains []string
}

// Inspector handles packet analysis and queue verdicts.
type Inspector struct {
	cfg            Config
	logger         *slog.Logger
	runtime        queueRuntime
	blockedDomains []string
}

func New(cfg Config, logger *slog.Logger) *Inspector {
	return newWithRuntime(cfg, logger, newQueueRuntime(logger, cfg.FailOpen))
}

func newWithRuntime(cfg Config, logger *slog.Logger, runtime queueRuntime) *Inspector {
	if cfg.Mode == "" {
		cfg.Mode = "skeleton"
	}
	if logger == nil {
		logger = slog.Default()
	}
	if runtime == nil {
		runtime = newQueueRuntime(logger, cfg.FailOpen)
	}

	return &Inspector{
		cfg:            cfg,
		logger:         logger,
		runtime:        runtime,
		blockedDomains: normalizeDomains(cfg.BlockedDomains),
	}
}

// WIP: AnalyzePacket parses an L3 packet and decides whether it should be accepted or dropped
func (i *Inspector) AnalyzePacket(packet []byte) Decision {
	tp, err := extractTransportPayload(packet)
	if err != nil {
		if i.cfg.FailOpen {
			return Decision{Verdict: VerdictAccept, Reason: "parse_error_fail_open"}
		}
		return Decision{Verdict: VerdictDrop, Reason: "parse_error_fail_closed"}
	}
	if len(tp.data) == 0 {
		return Decision{Verdict: VerdictAccept, Reason: "empty_transport_payload"}
	}

	if IsBitTorrentHandshake(tp.data) {
		return Decision{Verdict: VerdictDrop, Reason: "bittorrent_signature"}
	}

	if IsOpenVPN(tp.data, tp.isTCP) {
		return Decision{Verdict: VerdictDrop, Reason: "openvpn_signature"}
	}

	host, ok := ExtractHTTPHost(tp.data)
	if ok && i.isBlockedDomain(host) {
		return Decision{Verdict: VerdictDrop, Reason: "http_host_blocked"}
	}

	sni, ok := ExtractTLSSNI(tp.data)
	if ok && i.isBlockedDomain(sni) {
		return Decision{Verdict: VerdictDrop, Reason: "tls_sni_blocked"}
	}

	return Decision{Verdict: VerdictAccept, Reason: "no_match"}
}

// Run starts the NFQUEUE loop
func (i *Inspector) Run(ctx context.Context) error {
	i.logger.Info("inspector loop started", "mode", i.cfg.Mode, "queue_num", i.cfg.QueueNum, "blocked_domains", len(i.blockedDomains))

	err := i.runtime.Run(ctx, i.cfg.QueueNum, func(packetID uint32, packet []byte) Verdict {
		decision := i.AnalyzePacket(packet)
		if decision.Verdict == VerdictDrop {
			i.logger.Warn("packet dropped", "packet_id", packetID, "reason", decision.Reason)
		}
		return decision.Verdict
	})
	if err != nil {
		return fmt.Errorf("run queue runtime: %w", err)
	}

	i.logger.Info("inspector loop stopped")
	return nil
}

func (i *Inspector) isBlockedDomain(candidate string) bool {
	candidate = normalizeHost(candidate)
	if candidate == "" {
		return false
	}
	for _, blocked := range i.blockedDomains {
		if candidate == blocked || strings.HasSuffix(candidate, "."+blocked) {
			return true
		}
	}
	return false
}

func normalizeDomains(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		domain := strings.ToLower(strings.TrimSpace(value))
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

func extractTransportPayload(packet []byte) (transportPayload, error) {
	if len(packet) == 0 {
		return transportPayload{}, fmt.Errorf("empty packet")
	}

	var layerType gopacket.LayerType
	switch packet[0] >> 4 {
	case 4:
		layerType = layers.LayerTypeIPv4
	case 6:
		layerType = layers.LayerTypeIPv6
	default:
		return transportPayload{}, fmt.Errorf("unsupported packet format")
	}

	decoded := gopacket.NewPacket(packet, layerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if decoded.NetworkLayer() == nil {
		return transportPayload{}, fmt.Errorf("unsupported packet format")
	}

	if tcpLayer := decoded.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp == nil {
			return transportPayload{}, fmt.Errorf("invalid tcp layer")
		}
		return transportPayload{data: tcp.Payload, isTCP: true}, nil
	}

	if udpLayer := decoded.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp == nil {
			return transportPayload{}, fmt.Errorf("invalid udp layer")
		}
		return transportPayload{data: udp.Payload, isTCP: false}, nil
	}

	return transportPayload{}, fmt.Errorf("unsupported transport protocol")
}
