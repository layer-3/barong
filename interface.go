package barong

import (
	"context"
	"time"
)

// Client represents the public interface for interacting with the session service
type Client interface {
	// Challenge returns a challenge token
	Challenge() (Token, error)
	
	// Login verifies the challenge token and signature, and returns new tokens
	Login(challenge Token, signature, address string) (access Token, refresh Token, err error)
	
	// Refresh rotates the refresh token and returns new tokens
	Refresh(refresh Token) (access Token, newRefresh Token, err error)
	
	// Logout invalidates the provided tokens
	Logout(refresh Token, access Token) error
}

// Store represents the interface for storing and retrieving refresh token JTIs
type Store interface {
	// Set adds a key with a value and expiration time
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	
	// Get retrieves a value by key
	Get(ctx context.Context, key string) (string, error)
}

// EventPublisher represents an interface for publishing events
type EventPublisher interface {
	// Publish publishes an event to a topic
	Publish(topic string, data interface{}) error
}