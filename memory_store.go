package barong

import (
	"context"
	"sync"
	"time"
)

// MemoryStore implements the Store interface using an in-memory map
// This is primarily intended for testing purposes
type MemoryStore struct {
	data map[string]string
	mu   sync.RWMutex
}

// NewMemoryStore creates a new MemoryStore
func NewMemoryStore(ctx context.Context) *MemoryStore {
	return &MemoryStore{
		data: make(map[string]string),
	}
}

// Set stores a key with a value
// For MemoryStore, we ignore the TTL parameter as noted in the spec
func (s *MemoryStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.data[key] = value
	return nil
}

// Get retrieves a value by key
func (s *MemoryStore) Get(ctx context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	value, ok := s.data[key]
	if !ok {
		return "", ErrInvalidToken
	}
	
	return value, nil
}

// Clear removes all data from the store
// This is useful for testing to reset the store between tests
func (s *MemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.data = make(map[string]string)
}