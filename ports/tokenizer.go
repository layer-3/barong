package ports

import "github.com/layer-3/barong/core"

// Tokenizer converts between domain objects and tokens
type Tokenizer interface {
	// Challenge token operations
	ChallengeToToken(challenge *core.Challenge) (string, error)
	TokenToChallenge(token string) (*core.Challenge, error)

	// Session tokens operations
	SessionToAccessToken(session *core.Session) (string, error)
	AccessTokenToSession(token string) (*core.Session, error)
	SessionToRefreshToken(session *core.Session) (string, error)
	RefreshTokenToSession(token string) (*core.Session, error)

	// Verification helpers
	VerifySignature(challenge *core.Challenge, signature string, address string) error
}
