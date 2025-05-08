package barong

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/gin-gonic/gin"
	"github.com/layer-3/barong/internal/eth"
)

const (
	// LogoutTopic is the topic for logout events
	LogoutTopic = "auth.logout"
)

// LogoutEvent represents a logout event
type LogoutEvent struct {
	UserAddress string `json:"user_address"`
	TokenID     string `json:"token_id"`
}

// Service provides HTTP handlers for the session service
type Service struct {
	session  *Session
	store    Store
	signer   eth.Signer
	router   *gin.Engine
	publisher message.Publisher
}

// LoginRequest represents a login request
type LoginRequest struct {
	Challenge string `json:"challenge" binding:"required"`
	Signature string `json:"signature" binding:"required"`
	Address   string `json:"address" binding:"required"`
}

// RefreshRequest represents a refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	AccessToken  string `json:"access_token" binding:"required"`
}

// TokenResponse represents a token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// UserResponse represents a user response
type UserResponse struct {
	Address string `json:"address"`
}

// NewService creates a new service
func NewService(store Store, signer eth.Signer, publisher message.Publisher) *Service {
	router := gin.Default()
	
	session := NewSession(store, signer)
	
	service := &Service{
		session:   session,
		store:     store,
		signer:    signer,
		router:    router,
		publisher: publisher,
	}
	
	// Set up routes
	service.setupRoutes()
	
	return service
}

// setupRoutes sets up the HTTP routes
func (s *Service) setupRoutes() {
	// Auth routes
	auth := s.router.Group("/auth")
	{
		auth.POST("/challenge", s.handleChallenge)
		auth.POST("/login", s.handleLogin)
		auth.POST("/refresh", s.handleRefresh)
		auth.POST("/logout", s.handleLogout)
	}
	
	// API routes (protected)
	api := s.router.Group("/api")
	api.Use(s.authMiddleware())
	{
		api.GET("/me", s.handleMe)
		api.GET("/authorize", s.handleAuthorize)
	}
}

// authMiddleware checks if the request has a valid access token
func (s *Service) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header is required"})
			return
		}
		
		// Check for Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			return
		}
		
		// Extract token
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		
		// Parse token
		token, err := ParseToken(tokenStr, TokenTypeAccess)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		
		// Verify token
		if err := s.session.VerifyAccessToken(c.Request.Context(), token); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		
		// Get subject from token
		subject, err := token.GetSubject()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			return
		}
		
		// Set user address in context
		c.Set("user_address", subject)
		
		c.Next()
	}
}

// handleChallenge handles the challenge endpoint
func (s *Service) handleChallenge(c *gin.Context) {
	// Create challenge token
	token, err := s.session.CreateChallenge()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create challenge"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"token": token.String()})
}

// handleLogin handles the login endpoint
func (s *Service) handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	
	// Parse challenge token
	challengeToken, err := ParseToken(req.Challenge, TokenTypeChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid challenge token"})
		return
	}
	
	// Verify challenge
	if err := s.session.VerifyChallenge(c.Request.Context(), challengeToken, req.Signature, req.Address); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid challenge or signature"})
		return
	}
	
	// Create new tokens
	accessToken, refreshToken, err := s.session.CreateTokens()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create tokens"})
		return
	}
	
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken.String(),
		RefreshToken: refreshToken.String(),
	})
}

// handleRefresh handles the refresh endpoint
func (s *Service) handleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	
	// Parse refresh token
	refreshToken, err := ParseToken(req.RefreshToken, TokenTypeRefresh)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid refresh token"})
		return
	}
	
	// Rotate tokens
	accessToken, newRefreshToken, err := s.session.RotateTokens(c.Request.Context(), refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}
	
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken.String(),
		RefreshToken: newRefreshToken.String(),
	})
}

// handleLogout handles the logout endpoint
func (s *Service) handleLogout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	
	// Parse refresh token
	refreshToken, err := ParseToken(req.RefreshToken, TokenTypeRefresh)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid refresh token"})
		return
	}
	
	// Invalidate refresh token
	if err := s.session.InvalidateRefreshToken(c.Request.Context(), refreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to invalidate token"})
		return
	}
	
	// Get token ID and user address for the event
	tokenID, _ := refreshToken.GetJTI()
	userAddress, _ := refreshToken.GetSubject()
	
	// Publish logout event
	if s.publisher != nil {
		event := LogoutEvent{
			UserAddress: userAddress,
			TokenID:     tokenID,
		}
		
		eventBytes, err := json.Marshal(event)
		if err == nil {
			msg := message.NewMessage(tokenID, eventBytes)
			err = s.publisher.Publish(LogoutTopic, msg)
			if err != nil {
				// Just log the error, don't fail the request
				// In a real implementation, we would use a proper logger
				// fmt.Printf("Failed to publish logout event: %v\n", err)
			}
		}
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// handleMe handles the me endpoint
func (s *Service) handleMe(c *gin.Context) {
	// User address is set by the auth middleware
	userAddress, exists := c.Get("user_address")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	
	c.JSON(http.StatusOK, UserResponse{
		Address: userAddress.(string),
	})
}

// handleAuthorize handles the authorize endpoint
func (s *Service) handleAuthorize(c *gin.Context) {
	// If we got here, the auth middleware has already validated the token
	c.Status(http.StatusOK)
}

// Router returns the gin router
func (s *Service) Router() *gin.Engine {
	return s.router
}