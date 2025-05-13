package core

import "errors"

var (
	ErrTokenExpired     = errors.New("token has expired")
	ErrTokenInvalidated = errors.New("token has been invalidated")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidToken     = errors.New("invalid token")
	ErrInvalidChallenge = errors.New("invalid challenge")
)
