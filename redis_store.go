package barong

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore implements the Store interface using Redis
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a new RedisStore
func NewRedisStore(ctx context.Context, redisURL string) (*RedisStore, error) {
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(options)
	
	// Test connection
	_, err = client.Ping(ctx).Result()
	if err != nil {
		return nil, err
	}
	
	return &RedisStore{
		client: client,
	}, nil
}

// Set stores a key with a value and expiration time
func (s *RedisStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	err := s.client.Set(ctx, key, value, ttl).Err()
	if err != nil {
		return ErrStoreOperationFailed
	}
	return nil
}

// Get retrieves a value by key
func (s *RedisStore) Get(ctx context.Context, key string) (string, error) {
	value, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", ErrInvalidToken
		}
		return "", ErrStoreOperationFailed
	}
	return value, nil
}

// GetClient returns the Redis client
// This is used by the main application to share the Redis client with the Watermill publisher
func (s *RedisStore) GetClient() *redis.Client {
	return s.client
}

// Close closes the Redis connection
func (s *RedisStore) Close() error {
	return s.client.Close()
}