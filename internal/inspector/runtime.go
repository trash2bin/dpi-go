package inspector

import "context"

type queueRuntime interface {
	Run(ctx context.Context, queueNum uint16, decide func(packetID uint32, packet []byte) Verdict) error
}
