package tokenizer

import "github.com/golang-jwt/jwt/v5"

// ChallengeClaims combines standard claims with challenge-specific ones
type ChallengeClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce"`
}

// AccessClaims combines standard claims with access-specific ones
type AccessClaims struct {
	jwt.RegisteredClaims
	RefreshID string `json:"rid"` // ID of the refresh token
}

// RefreshClaims are just the standard claims for refresh tokens
type RefreshClaims struct {
	jwt.RegisteredClaims
}
