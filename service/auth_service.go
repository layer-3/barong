package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/layer-3/barong/core"
	"github.com/layer-3/barong/ports"
)

// AuthService handles authentication business logic
type AuthService struct {
	tokenizer ports.Tokenizer
	store     ports.Store
	eventPub  ports.EventPublisher

	challengeTTL time.Duration
	accessTTL    time.Duration
	refreshTTL   time.Duration
}

// NewAuthService creates a new authentication service
func NewAuthService(
	tokenizer ports.Tokenizer,
	store ports.Store,
	eventPub ports.EventPublisher,
) *AuthService {
	return &AuthService{
		tokenizer:    tokenizer,
		store:        store,
		eventPub:     eventPub,
		challengeTTL: 5 * time.Minute,
		accessTTL:    5 * time.Minute,
		refreshTTL:   5 * 24 * time.Hour, // 5 days
	}
}

// CreateChallenge generates a new authentication challenge
func (s *AuthService) CreateChallenge(address string) (string, error) {
	// Generate random nonce
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	now := time.Now()
	challenge := &core.Challenge{
		ID:        uuid.New().String(),
		Address:   address,
		Nonce:     hex.EncodeToString(nonceBytes),
		IssuedAt:  now,
		ExpiresAt: now.Add(s.challengeTTL),
	}

	// Convert to token
	token, err := s.tokenizer.ChallengeToToken(challenge)
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	return token, nil
}

// Login authenticates a user using their signed challenge
func (s *AuthService) Login(ctx context.Context, challengeToken, signature, address string) (string, string, error) {
	// Parse challenge token
	challenge, err := s.tokenizer.TokenToChallenge(challengeToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid challenge token: %w", err)
	}

	// Verify the signature
	if err := s.tokenizer.VerifySignature(challenge, signature, address); err != nil {
		return "", "", fmt.Errorf("signature verification failed: %w", err)
	}

	// Create new session
	refreshID := uuid.New().String()
	now := time.Now()
	session := &core.Session{
		ID:            uuid.New().String(),
		Address:       address,
		IssuedAt:      now,
		RefreshExpiry: now.Add(s.refreshTTL),
		AccessExpiry:  now.Add(s.accessTTL),
		RefreshID:     refreshID,
	}

	// Generate tokens
	accessToken, err := s.tokenizer.SessionToAccessToken(session)
	if err != nil {
		return "", "", fmt.Errorf("failed to create access token: %w", err)
	}

	refreshToken, err := s.tokenizer.SessionToRefreshToken(session)
	if err != nil {
		return "", "", fmt.Errorf("failed to create refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// Refresh rotates the refresh token and issues new access and refresh tokens
func (s *AuthService) Refresh(ctx context.Context, refreshTokenStr string) (string, string, error) {
	// Parse and validate the refresh token
	session, err := s.tokenizer.RefreshTokenToSession(refreshTokenStr)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if the token has expired
	if time.Now().After(session.RefreshExpiry) {
		return "", "", core.ErrTokenExpired
	}

	// Check if the token has been invalidated
	invalidated, err := s.store.IsTokenInvalidated(ctx, session.RefreshID)
	if err != nil {
		return "", "", fmt.Errorf("failed to check token invalidation: %w", err)
	}

	if invalidated {
		return "", "", core.ErrTokenInvalidated
	}

	// Invalidate the old refresh token
	// We use the remaining time from the original token's expiry to set the TTL
	remainingTime := time.Until(session.RefreshExpiry)
	if err := s.store.InvalidateToken(ctx, session.RefreshID, remainingTime); err != nil {
		return "", "", fmt.Errorf("failed to invalidate old token: %w", err)
	}

	// Create new refresh and access tokens
	now := time.Now()
	newRefreshID := uuid.New().String()

	newSession := &core.Session{
		ID:            uuid.New().String(),
		Address:       session.Address,
		IssuedAt:      now,
		RefreshExpiry: now.Add(s.refreshTTL),
		AccessExpiry:  now.Add(s.accessTTL),
		RefreshID:     newRefreshID,
	}

	// Generate new tokens
	accessToken, err := s.tokenizer.SessionToAccessToken(newSession)
	if err != nil {
		return "", "", fmt.Errorf("failed to create new access token: %w", err)
	}

	refreshToken, err := s.tokenizer.SessionToRefreshToken(newSession)
	if err != nil {
		return "", "", fmt.Errorf("failed to create new refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// Logout invalidates a refresh token
func (s *AuthService) Logout(ctx context.Context, refreshTokenStr string) error {
	// Parse the refresh token
	session, err := s.tokenizer.RefreshTokenToSession(refreshTokenStr)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	// Even if the token is expired, we still want to invalidate it
	// This ensures that even expired tokens can't be reused later
	var remainingTime time.Duration

	// If the token is already expired, use a short TTL for the invalidation record
	if time.Now().After(session.RefreshExpiry) {
		// Use a minimum TTL (e.g., 1 hour) to ensure the token can't be reused
		// even if clocks are slightly out of sync
		remainingTime = time.Hour
	} else {
		// Use the remaining time from the token's expiry
		remainingTime = time.Until(session.RefreshExpiry)
	}

	// Invalidate the refresh token
	if err := s.store.InvalidateToken(ctx, session.RefreshID, remainingTime); err != nil {
		return fmt.Errorf("failed to invalidate token: %w", err)
	}

	// Publish logout event for cross-instance notifications
	// This allows other instances to be notified about the logout
	if err := s.eventPub.PublishLogout(ctx, session.Address, session.RefreshID); err != nil {
		// Log the error but don't fail the logout operation
		// The token is already invalidated in the store, which is the critical part
		fmt.Printf("Warning: Failed to publish logout event: %v\n", err)
	}

	return nil
}

func (s *AuthService) ValidateAccessToken(ctx context.Context, accessToken string) (*core.Session, error) {
	// Parse and validate the access token
	session, err := s.tokenizer.AccessTokenToSession(accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	// Check if the token has expired
	if time.Now().After(session.AccessExpiry) {
		return nil, core.ErrTokenExpired
	}

	// Check if the associated refresh token has been invalidated
	// This provides an extra layer of security by allowing access tokens
	// to be invalidated when a refresh token is invalidated
	if session.RefreshID != "" {
		invalidated, err := s.store.IsTokenInvalidated(ctx, session.RefreshID)
		if err != nil {
			return nil, fmt.Errorf("failed to check token invalidation: %w", err)
		}

		if invalidated {
			return nil, core.ErrTokenInvalidated
		}
	}

	return session, nil
}
