package store

import (
	"context"
	"sync"
	"time"

	"github.com/layer-3/barong/ports"
)

// MemoryStore is an in-memory implementation of the Store interface
type MemoryStore struct {
	invalidatedTokens map[string]time.Time
	mu                sync.RWMutex
}

// NewMemoryStore creates a new in-memory store
func NewMemoryStore() ports.Store {
	return &MemoryStore{
		invalidatedTokens: make(map[string]time.Time),
	}
}

// InvalidateToken marks a token as invalidated
func (s *MemoryStore) InvalidateToken(ctx context.Context, tokenID string, expiry time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiryTime := time.Now().Add(expiry)
	s.invalidatedTokens[tokenID] = expiryTime

	// Start a cleanup goroutine
	go func() {
		time.Sleep(expiry)

		s.mu.Lock()
		defer s.mu.Unlock()

		// Only delete if the expiry time hasn't changed
		if storedExpiry, exists := s.invalidatedTokens[tokenID]; exists && !storedExpiry.After(expiryTime) {
			delete(s.invalidatedTokens, tokenID)
		}
	}()

	return nil
}

// IsTokenInvalidated checks if a token is invalidated
func (s *MemoryStore) IsTokenInvalidated(ctx context.Context, tokenID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiryTime, exists := s.invalidatedTokens[tokenID]
	if !exists {
		return false, nil
	}

	// Check if the token invalidation has expired
	if time.Now().After(expiryTime) {
		return false, nil
	}

	return true, nil
}
