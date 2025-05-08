package barong

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/layer-3/barong/internal/eth"
)

// TokenType represents the type of token
type TokenType string

const (
	// TokenTypeChallenge represents a challenge token
	TokenTypeChallenge TokenType = "session:challenge"

	// TokenTypeAccess represents an access token
	TokenTypeAccess TokenType = "session:access"

	// TokenTypeRefresh represents a refresh token
	TokenTypeRefresh TokenType = "session:refresh"

	// DefaultChallengeExpiry is the default expiration time for challenge tokens
	DefaultChallengeExpiry = 5 * time.Minute

	// DefaultAccessExpiry is the default expiration time for access tokens
	DefaultAccessExpiry = 5 * time.Minute

	// DefaultRefreshExpiry is the default expiration time for refresh tokens
	DefaultRefreshExpiry = 120 * time.Hour // 5 days
)

// Token represents a JWT token
type Token struct {
	jwt     string
	claims  jwt.Claims
	signer  eth.Signer
	tokenType TokenType
}

// ChallengeClaims represents the claims for a challenge token
type ChallengeClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce"`
}

// AccessClaims represents the claims for an access token
type AccessClaims struct {
	jwt.RegisteredClaims
	RefreshID string `json:"rid,omitempty"`
}

// RefreshClaims represents the claims for a refresh token
type RefreshClaims struct {
	jwt.RegisteredClaims
}

// NewToken creates a new token based on the provided claims and signer
func NewToken(address string, tokenType TokenType, signer eth.Signer) (Token, error) {
	jti := uuid.New().String()
	now := time.Now()
	var claims jwt.Claims
	var expiresAt time.Time

	switch tokenType {
	case TokenTypeChallenge:
		nonce, err := generateNonce(32)
		if err != nil {
			return Token{}, err
		}
		expiresAt = now.Add(DefaultChallengeExpiry)
		claims = &ChallengeClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   address,
				Audience:  jwt.ClaimStrings{string(TokenTypeChallenge)},
				ExpiresAt: jwt.NewNumericDate(expiresAt),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        jti,
			},
			Nonce: nonce,
		}

	case TokenTypeAccess:
		expiresAt = now.Add(DefaultAccessExpiry)
		claims = &AccessClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   address,
				Audience:  jwt.ClaimStrings{string(TokenTypeAccess)},
				ExpiresAt: jwt.NewNumericDate(expiresAt),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        jti,
			},
		}

	case TokenTypeRefresh:
		expiresAt = now.Add(DefaultRefreshExpiry)
		claims = &RefreshClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   address,
				Audience:  jwt.ClaimStrings{string(TokenTypeRefresh)},
				ExpiresAt: jwt.NewNumericDate(expiresAt),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        jti,
			},
		}

	default:
		return Token{}, ErrInvalidToken
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	
	// Sign the token
	sig, err := signer.Sign([]byte(token.Raw))
	if err != nil {
		return Token{}, err
	}
	
	// ES256 expects the signature in the format R || S
	jwtSignature := append(sig.R, sig.S...)
	
	// Set the signature
	token.Signature = base64.RawURLEncoding.EncodeToString(jwtSignature)

	// Encode the token
	tokenString := token.Raw + "." + token.Signature

	return Token{
		jwt:      tokenString,
		claims:   claims,
		signer:   signer,
		tokenType: tokenType,
	}, nil
}

// SetRefreshID sets the refresh ID for an access token
func (t *Token) SetRefreshID(refreshID string) error {
	if t.tokenType != TokenTypeAccess {
		return ErrInvalidToken
	}

	accessClaims, ok := t.claims.(*AccessClaims)
	if !ok {
		return ErrInvalidClaims
	}

	accessClaims.RefreshID = refreshID
	
	// Re-create the token with updated claims
	token := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	
	// Sign the token
	sig, err := t.signer.Sign([]byte(token.Raw))
	if err != nil {
		return err
	}
	
	// ES256 expects the signature in the format R || S
	jwtSignature := append(sig.R, sig.S...)
	
	// Set the signature
	token.Signature = base64.RawURLEncoding.EncodeToString(jwtSignature)

	// Encode the token
	t.jwt = token.Raw + "." + token.Signature
	t.claims = accessClaims

	return nil
}

// String returns the JWT string representation of the token
func (t Token) String() string {
	return t.jwt
}

// Type returns the token type
func (t Token) Type() TokenType {
	return t.tokenType
}

// Claims returns the token claims
func (t Token) Claims() jwt.Claims {
	return t.claims
}

// GetNonce returns the nonce from a challenge token
func (t Token) GetNonce() (string, error) {
	if t.tokenType != TokenTypeChallenge {
		return "", ErrInvalidToken
	}

	challengeClaims, ok := t.claims.(*ChallengeClaims)
	if !ok {
		return "", ErrInvalidClaims
	}

	return challengeClaims.Nonce, nil
}

// GetJTI returns the JTI from a token
func (t Token) GetJTI() (string, error) {
	id, err := t.claims.GetID()
	if err != nil {
		return "", ErrInvalidClaims
	}
	return id, nil
}

// GetSubject returns the subject from a token
func (t Token) GetSubject() (string, error) {
	sub, err := t.claims.GetSubject()
	if err != nil {
		return "", ErrInvalidClaims
	}
	return sub, nil
}

// GetRefreshID returns the refresh ID from an access token
func (t Token) GetRefreshID() (string, error) {
	if t.tokenType != TokenTypeAccess {
		return "", ErrInvalidToken
	}

	accessClaims, ok := t.claims.(*AccessClaims)
	if !ok {
		return "", ErrInvalidClaims
	}

	return accessClaims.RefreshID, nil
}

// GetExpiresAt returns the expiration time of the token
func (t Token) GetExpiresAt() (time.Time, error) {
	exp, err := t.claims.GetExpirationTime()
	if err != nil {
		return time.Time{}, ErrInvalidClaims
	}
	return exp.Time, nil
}

// Validate validates the token
func (t Token) Validate() error {
	// Check token type audience
	aud, err := t.claims.GetAudience()
	if err != nil {
		return ErrInvalidClaims
	}
	
	if len(aud) == 0 || aud[0] != string(t.tokenType) {
		return ErrInvalidAudience
	}
	
	// Check expiration
	exp, err := t.claims.GetExpirationTime()
	if err != nil {
		return ErrInvalidClaims
	}
	
	if exp.Before(time.Now()) {
		return ErrTokenExpired
	}
	
	return nil
}

// ParseToken parses a JWT string and returns a Token
func ParseToken(tokenString string, expectedType TokenType) (Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, createClaimsForType(expectedType), keyFunc)
	if err != nil {
		return Token{}, ErrInvalidToken
	}
	
	if !token.Valid {
		return Token{}, ErrInvalidToken
	}
	
	// Verify audience
	claims := token.Claims
	aud, err := claims.GetAudience()
	if err != nil {
		return Token{}, ErrInvalidClaims
	}
	
	if len(aud) == 0 || aud[0] != string(expectedType) {
		return Token{}, ErrInvalidAudience
	}
	
	return Token{
		jwt:      tokenString,
		claims:   claims,
		tokenType: expectedType,
	}, nil
}

// createClaimsForType creates the appropriate claims object based on token type
func createClaimsForType(tokenType TokenType) jwt.Claims {
	switch tokenType {
	case TokenTypeChallenge:
		return &ChallengeClaims{}
	case TokenTypeAccess:
		return &AccessClaims{}
	case TokenTypeRefresh:
		return &RefreshClaims{}
	default:
		return jwt.MapClaims{}
	}
}

// keyFunc is used by jwt.Parse to validate the signing method
func keyFunc(token *jwt.Token) (interface{}, error) {
	// Verify signing method
	if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
		return nil, ErrInvalidSigningMethod
	}
	
	// In a real implementation, we would retrieve the public key 
	// associated with the token here. For simplicity, we just validate
	// the signing method.
	return nil, nil
}

// generateNonce generates a secure random nonce of the specified length
func generateNonce(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}