package ports

import (
	"context"
	"time"
)

// Store interface for token invalidation
type Store interface {
	InvalidateToken(ctx context.Context, tokenID string, expiry time.Duration) error
	IsTokenInvalidated(ctx context.Context, tokenID string) (bool, error)
}
