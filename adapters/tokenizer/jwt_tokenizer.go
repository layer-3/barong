package tokenizer

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang-jwt/jwt/v5"
	"github.com/layer-3/barong/core"
	"github.com/layer-3/barong/internal/eth"
	"github.com/layer-3/barong/ports"
)

const AudienceChallenge = "session:challenge"
const AudienceAccess = "session:access"
const AudienceRefresh = "session:refresh"

// JWTTokenizer implements the Tokenizer interface using JWT
type JWTTokenizer struct {
	signKey *ecdsa.PrivateKey
}

// NewJWTTokenizer creates a new JWT tokenizer
func NewJWTTokenizer(signKey *ecdsa.PrivateKey) ports.Tokenizer {
	return &JWTTokenizer{signKey: signKey}
}

// ChallengeToToken converts a Challenge to a JWT token
func (j *JWTTokenizer) ChallengeToToken(challenge *core.Challenge) (string, error) {
	claims := ChallengeClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   challenge.Address,
			ID:        challenge.ID,
			ExpiresAt: jwt.NewNumericDate(challenge.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(challenge.IssuedAt),
			Audience:  jwt.ClaimStrings{AudienceChallenge},
		},
		Nonce: challenge.Nonce,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(j.signKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// TokenToChallenge converts a JWT token to a Challenge
func (j *JWTTokenizer) TokenToChallenge(tokenStr string) (*core.Challenge, error) {
	// Parse token
	token, err := jwt.ParseWithClaims(tokenStr, &ChallengeClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.signKey.PublicKey, nil
	}, jwt.WithAudience(AudienceChallenge))

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Validate token
	if !token.Valid {
		return nil, core.ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(*ChallengeClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Create challenge from claims
	challenge := &core.Challenge{
		ID:        claims.ID,
		Address:   claims.Subject,
		Nonce:     claims.Nonce,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	return challenge, nil
}

// SessionToAccessToken converts a Session to an access JWT token
func (j *JWTTokenizer) SessionToAccessToken(session *core.Session) (string, error) {
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   session.Address,
			ID:        session.ID,
			ExpiresAt: jwt.NewNumericDate(session.AccessExpiry),
			IssuedAt:  jwt.NewNumericDate(session.IssuedAt),
			Audience:  jwt.ClaimStrings{AudienceAccess},
		},
		RefreshID: session.RefreshID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(j.signKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, nil
}

// SessionToRefreshToken converts a Session to a refresh JWT token
func (j *JWTTokenizer) SessionToRefreshToken(session *core.Session) (string, error) {
	claims := RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   session.Address,
			ID:        session.RefreshID, // Use RefreshID as the JWT ID for the refresh token
			ExpiresAt: jwt.NewNumericDate(session.RefreshExpiry),
			IssuedAt:  jwt.NewNumericDate(session.IssuedAt),
			Audience:  jwt.ClaimStrings{AudienceRefresh},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(j.signKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return signedToken, nil
}

// AccessTokenToSession parses an access token and returns the associated session
func (j *JWTTokenizer) AccessTokenToSession(tokenStr string) (*core.Session, error) {
	// Parse token with custom claims
	token, err := jwt.ParseWithClaims(tokenStr, &AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.signKey.PublicKey, nil
	}, jwt.WithAudience(AudienceAccess))

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Validate token
	if !token.Valid {
		return nil, core.ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(*AccessClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Create session from claims
	session := &core.Session{
		ID:           claims.ID,
		Address:      claims.Subject,
		IssuedAt:     claims.IssuedAt.Time,
		AccessExpiry: claims.ExpiresAt.Time,
		RefreshID:    claims.RefreshID,
	}

	return session, nil
}

// RefreshTokenToSession parses a refresh token and returns the associated session
func (j *JWTTokenizer) RefreshTokenToSession(tokenStr string) (*core.Session, error) {
	// Parse token with custom claims
	token, err := jwt.ParseWithClaims(tokenStr, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.signKey.PublicKey, nil
	}, jwt.WithAudience(AudienceRefresh))

	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	// Validate token
	if !token.Valid {
		return nil, core.ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(*RefreshClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Create session from claims
	// Note: For refresh tokens, we only have partial session info
	// The AccessExpiry will be zeroed, which is fine since it's not used
	// when processing refresh tokens
	session := &core.Session{
		Address:       claims.Subject,
		IssuedAt:      claims.IssuedAt.Time,
		RefreshExpiry: claims.ExpiresAt.Time,
		RefreshID:     claims.ID, // The JWT ID is the refresh token ID
	}

	return session, nil
}

// VerifySignature verifies an Ethereum signature against a challenge
func (j *JWTTokenizer) VerifySignature(challenge *core.Challenge, signatureStr string, addressStr string) error {
	// Verify that the address matches the challenge
	if challenge.Address != addressStr {
		return fmt.Errorf("address mismatch")
	}
	decodedSig, err := hexutil.Decode(signatureStr)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", core.ErrInvalidSignature)
	}
	if len(decodedSig) != 65 {
		return fmt.Errorf("signature must be 65 bytes: %w", core.ErrInvalidSignature)
	}

	// Define a sample EIP712Domain
	domain := eth.EIP712Domain{
		Name:              "Example DApp",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: common.HexToAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
	}

	msg := eth.NonceMessage(challenge.Nonce)

	expectedAddr := common.HexToAddress(addressStr)

	verified, err := eth.VerifySignatureAgainstAddress(domain, msg, decodedSig, expectedAddr)
	if err != nil {
		return fmt.Errorf("EIP-712 signature verification failed: %w", err)
	}
	if !verified {
		return core.ErrInvalidSignature
	}

	return nil
}
