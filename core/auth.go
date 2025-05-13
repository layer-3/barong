package core

import "time"

// Challenge represents an authentication challenge
type Challenge struct {
	ID        string    // Unique identifier for the challenge
	Address   string    // Ethereum address of the user
	Nonce     string    // Random nonce to be signed
	IssuedAt  time.Time // When the challenge was created
	ExpiresAt time.Time // When the challenge expires
}

// Session represents an authenticated user session
type Session struct {
	ID            string    // Unique session identifier
	Address       string    // Ethereum address of the user
	IssuedAt      time.Time // When the session was created
	RefreshExpiry time.Time // When the refresh capability expires
	AccessExpiry  time.Time // When the access capability expires
	RefreshID     string    // Unique identifier for the refresh token
}
