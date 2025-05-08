package barong

import (
	"context"
	"fmt"
	"time"

	"github.com/layer-3/barong/internal/eth"
)

// Session represents a user session
type Session struct {
	store   Store
	signer  eth.Signer
	address string
}

// NewSession creates a new session
func NewSession(store Store, signer eth.Signer) *Session {
	return &Session{
		store:  store,
		signer: signer,
	}
}

// CreateChallenge creates a new challenge token
func (s *Session) CreateChallenge() (Token, error) {
	// We don't have an address yet for challenge tokens, so we use an empty string
	// The address will be provided during login
	token, err := NewToken("", TokenTypeChallenge, s.signer)
	if err != nil {
		return Token{}, err
	}
	
	return token, nil
}

// VerifyChallenge verifies a challenge token and its signature
func (s *Session) VerifyChallenge(ctx context.Context, challengeToken Token, signature string, address string) error {
	// Validate the challenge token
	if err := challengeToken.Validate(); err != nil {
		return err
	}
	
	// Check if token is of correct type
	if challengeToken.Type() != TokenTypeChallenge {
		return ErrInvalidToken
	}
	
	// Get nonce from challenge token
	nonce, err := challengeToken.GetNonce()
	if err != nil {
		return err
	}
	
	// TODO: Verify the signature against the nonce using eth.VerifySignature
	// This would involve:
	// 1. Converting the hex signature to bytes
	// 2. Creating the appropriate EIP712 domain and message
	// 3. Using eth.VerifySignature to verify
	
	// For now, we'll assume the signature is valid
	// In a real implementation, this would need proper signature verification
	
	// Set the address for the session
	s.address = address
	
	return nil
}

// CreateTokens creates new access and refresh tokens
func (s *Session) CreateTokens() (Token, Token, error) {
	if s.address == "" {
		return Token{}, Token{}, ErrInvalidAddress
	}
	
	// Create refresh token
	refreshToken, err := NewToken(s.address, TokenTypeRefresh, s.signer)
	if err != nil {
		return Token{}, Token{}, err
	}
	
	// Create access token
	accessToken, err := NewToken(s.address, TokenTypeAccess, s.signer)
	if err != nil {
		return Token{}, Token{}, err
	}
	
	// Get refresh token JTI
	refreshJTI, err := refreshToken.GetJTI()
	if err != nil {
		return Token{}, Token{}, err
	}
	
	// Set the refresh JTI in the access token
	err = accessToken.SetRefreshID(refreshJTI)
	if err != nil {
		return Token{}, Token{}, err
	}
	
	return accessToken, refreshToken, nil
}

// RotateTokens verifies the refresh token and creates new tokens
func (s *Session) RotateTokens(ctx context.Context, refreshToken Token) (Token, Token, error) {
	// Validate the refresh token
	if err := refreshToken.Validate(); err != nil {
		return Token{}, Token{}, err
	}
	
	// Check if token is of correct type
	if refreshToken.Type() != TokenTypeRefresh {
		return Token{}, Token{}, ErrInvalidToken
	}
	
	// Get token JTI
	jti, err := refreshToken.GetJTI()
	if err != nil {
		return Token{}, Token{}, err
	}
	
	// Check if token is revoked
	key := fmt.Sprintf("revoked:%s", jti)
	_, err = s.store.Get(ctx, key)
	if err == nil {
		// Token exists in revocation store, it's been revoked
		return Token{}, Token{}, ErrTokenRevoked
	}
	
	// Get subject (address) from refresh token
	subject, err := refreshToken.GetSubject()
	if err != nil {
		return Token{}, Token{}, err
	}
	
	// Set address for new tokens
	s.address = subject
	
	// Create new tokens
	accessToken, newRefreshToken, err := s.CreateTokens()
	if err != nil {
		return Token{}, Token{}, err
	}
	
	// Invalidate old refresh token
	// Calculate token remaining lifetime
	expiresAt, err := refreshToken.GetExpiresAt()
	if err != nil {
		return Token{}, Token{}, err
	}
	remainingTTL := time.Until(expiresAt)
	
	// Store the revoked token with TTL
	err = s.store.Set(ctx, key, "revoked", remainingTTL)
	if err != nil {
		return Token{}, Token{}, ErrStoreOperationFailed
	}
	
	return accessToken, newRefreshToken, nil
}

// InvalidateRefreshToken invalidates a refresh token
func (s *Session) InvalidateRefreshToken(ctx context.Context, refreshToken Token) error {
	// Validate the refresh token
	if err := refreshToken.Validate(); err != nil {
		return err
	}
	
	// Check if token is of correct type
	if refreshToken.Type() != TokenTypeRefresh {
		return ErrInvalidToken
	}
	
	// Get token JTI
	jti, err := refreshToken.GetJTI()
	if err != nil {
		return err
	}
	
	// Get token expiration
	expiresAt, err := refreshToken.GetExpiresAt()
	if err != nil {
		return err
	}
	
	// Calculate TTL
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired
		return nil
	}
	
	// Store in revocation list
	key := fmt.Sprintf("revoked:%s", jti)
	err = s.store.Set(ctx, key, "revoked", ttl)
	if err != nil {
		return ErrStoreOperationFailed
	}
	
	return nil
}

// VerifyAccessToken verifies an access token
func (s *Session) VerifyAccessToken(ctx context.Context, accessToken Token) error {
	// Validate the access token
	if err := accessToken.Validate(); err != nil {
		return err
	}
	
	// Check if token is of correct type
	if accessToken.Type() != TokenTypeAccess {
		return ErrInvalidToken
	}
	
	// Get refresh token JTI
	refreshJTI, err := accessToken.GetRefreshID()
	if err != nil {
		return err
	}
	
	// Check if the associated refresh token has been revoked
	key := fmt.Sprintf("revoked:%s", refreshJTI)
	_, err = s.store.Get(ctx, key)
	if err == nil {
		// Associated refresh token has been revoked
		return ErrTokenRevoked
	}
	
	return nil
}