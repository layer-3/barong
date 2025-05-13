package store

import (
	"context"
	"fmt"
	"time"

	"github.com/layer-3/barong/ports"
	"github.com/redis/go-redis/v9"
)

// RedisStore is a Redis implementation of the Store interface
type RedisStore struct {
	client *redis.Client
	prefix string
}

// NewRedisStore creates a new Redis store
func NewRedisStore(client *redis.Client) ports.Store {
	return &RedisStore{
		client: client,
		prefix: "barong:invalidated:",
	}
}

// InvalidateToken marks a token as invalidated in Redis
func (s *RedisStore) InvalidateToken(ctx context.Context, tokenID string, expiry time.Duration) error {
	key := s.prefix + tokenID

	// Set key with expiration
	if err := s.client.Set(ctx, key, "1", expiry).Err(); err != nil {
		return fmt.Errorf("failed to invalidate token: %w", err)
	}

	return nil
}

// IsTokenInvalidated checks if a token is invalidated in Redis
func (s *RedisStore) IsTokenInvalidated(ctx context.Context, tokenID string) (bool, error) {
	key := s.prefix + tokenID

	// Check if key exists
	val, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check token invalidation: %w", err)
	}

	return val > 0, nil
}
