//go:build !linux

package inspector

import (
	"context"
	"log/slog"
)

type noopQueueRuntime struct {
	logger *slog.Logger
}

func newQueueRuntime(logger *slog.Logger, _ bool) queueRuntime {
	if logger == nil {
		logger = slog.Default()
	}
	return &noopQueueRuntime{logger: logger}
}

func (r *noopQueueRuntime) Run(ctx context.Context, queueNum uint16, _ func(packetID uint32, packet []byte) Verdict) error {
	r.logger.Warn("nfqueue runtime is disabled on non-linux OS", "queue_num", queueNum)
	<-ctx.Done()
	return nil
}
