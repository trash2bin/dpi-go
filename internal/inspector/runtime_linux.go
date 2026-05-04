//go:build linux

package inspector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
)

type linuxQueueRuntime struct {
	logger   *slog.Logger
	failOpen bool
}

func newQueueRuntime(logger *slog.Logger, failOpen bool) queueRuntime {
	if logger == nil {
		logger = slog.Default()
	}
	return &linuxQueueRuntime{logger: logger, failOpen: failOpen}
}

func (r *linuxQueueRuntime) Run(ctx context.Context, queueNum uint16, decide func(packetID uint32, packet []byte) Verdict) error {
	cfg := nfqueue.Config{
		NfQueue:      queueNum,
		MaxQueueLen:  1024,
		MaxPacketLen: 0xffff,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 3 * time.Second,
	}
	if r.failOpen {
		cfg.Flags = nfqueue.NfQaCfgFlagFailOpen
	}

	nfq, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("open nfqueue: %w", err)
	}
	defer func() {
		if closeErr := nfq.Close(); closeErr != nil {
			r.logger.Error("close nfqueue failed", "error", closeErr)
		}
	}()

	err = nfq.RegisterWithErrorFunc(ctx, func(attr nfqueue.Attribute) int {
		if attr.PacketID == nil {
			r.logger.Debug("skip packet without id")
			return 0
		}
		packetID := *attr.PacketID
		var payload []byte
		if attr.Payload != nil {
			payload = *attr.Payload
		}

		verdict := decide(packetID, payload)
		nfVerdict := nfqueue.NfAccept
		if verdict == VerdictDrop {
			nfVerdict = nfqueue.NfDrop
		}
		if setErr := nfq.SetVerdict(packetID, nfVerdict); setErr != nil {
			r.logger.Error("set nfqueue verdict failed", "packet_id", packetID, "error", setErr)
		}
		return 0
	}, func(cbErr error) int {
		if cbErr == nil {
			return 0
		}
		r.logger.Error("nfqueue callback error", "error", cbErr)
		return 0
	})

	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("register nfqueue callback: %w", err)
	}

	// ← без этого функция сразу возвращается
	// и nfq закрывается через defer до того как придёт хоть один пакет
	<-ctx.Done()

	return nil
}
