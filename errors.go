package barong

import (
	"errors"
)

var (
	// ErrTokenExpired is returned when a token has expired
	ErrTokenExpired = errors.New("token has expired")

	// ErrInvalidToken is returned when a token is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrInvalidSignature is returned when a signature is invalid
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidSigningMethod is returned when the signing method is not ES256
	ErrInvalidSigningMethod = errors.New("unexpected signing method")

	// ErrInvalidAudience is returned when the token audience is not as expected
	ErrInvalidAudience = errors.New("invalid audience")

	// ErrInvalidClaims is returned when the token claims are invalid
	ErrInvalidClaims = errors.New("invalid claims")

	// ErrTokenRevoked is returned when a token has been revoked
	ErrTokenRevoked = errors.New("token has been revoked")

	// ErrInvalidNonce is returned when the nonce is invalid
	ErrInvalidNonce = errors.New("invalid nonce")

	// ErrInvalidAddress is returned when the address is invalid
	ErrInvalidAddress = errors.New("invalid ethereum address")

	// ErrStoreOperationFailed is returned when a store operation fails
	ErrStoreOperationFailed = errors.New("store operation failed")

	// ErrSessionInvalid is returned when a session is invalid
	ErrSessionInvalid = errors.New("session is invalid")
)