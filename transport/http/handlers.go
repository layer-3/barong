package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/layer-3/barong/core"
	"github.com/layer-3/barong/service"
)

// AuthHandlers contains HTTP handlers for auth endpoints
type AuthHandlers struct {
	authService *service.AuthService
}

// NewAuthHandlers creates new auth handlers
func NewAuthHandlers(authService *service.AuthService) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
	}
}

// Challenge handles the challenge request
func (h *AuthHandlers) Challenge(c *gin.Context) {
	var req struct {
		Address string `json:"address" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	token, err := h.authService.CreateChallenge(req.Address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create challenge"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// Login handles the login request
func (h *AuthHandlers) Login(c *gin.Context) {
	var req struct {
		ChallengeToken string `json:"challenge_token" binding:"required"`
		Signature      string `json:"signature" binding:"required"`
		Address        string `json:"address" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	accessToken, refreshToken, err := h.authService.Login(c.Request.Context(), req.ChallengeToken, req.Signature, req.Address)
	if err != nil {
		statusCode := http.StatusInternalServerError
		errorMsg := "Authentication failed"

		// Map specific errors to appropriate status codes
		switch err {
		case core.ErrInvalidChallenge, core.ErrInvalidToken:
			statusCode = http.StatusBadRequest
			errorMsg = "Invalid challenge token"
		case core.ErrTokenExpired:
			statusCode = http.StatusBadRequest
			errorMsg = "Challenge token expired"
		case core.ErrInvalidSignature:
			statusCode = http.StatusUnauthorized
			errorMsg = "Invalid signature"
		}

		c.JSON(statusCode, gin.H{"error": errorMsg})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    300, // 5 minutes in seconds
	})
}

// Refresh handles token refresh
func (h *AuthHandlers) Refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	accessToken, refreshToken, err := h.authService.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		statusCode := http.StatusInternalServerError
		errorMsg := "Failed to refresh tokens"

		// Map specific errors to appropriate status codes
		switch err {
		case core.ErrInvalidToken:
			statusCode = http.StatusBadRequest
			errorMsg = "Invalid refresh token"
		case core.ErrTokenExpired:
			statusCode = http.StatusUnauthorized
			errorMsg = "Refresh token expired"
		case core.ErrTokenInvalidated:
			statusCode = http.StatusUnauthorized
			errorMsg = "Refresh token has been invalidated"
		}

		c.JSON(statusCode, gin.H{"error": errorMsg})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    300, // 5 minutes in seconds
	})
}

// Logout handles session logout
func (h *AuthHandlers) Logout(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Access token is optional - we only need refresh token to invalidate the session
	err := h.authService.Logout(c.Request.Context(), req.RefreshToken)
	if err != nil {
		statusCode := http.StatusInternalServerError
		errorMsg := "Failed to logout"

		// Map specific errors to appropriate status codes
		switch err {
		case core.ErrInvalidToken:
			statusCode = http.StatusBadRequest
			errorMsg = "Invalid refresh token"
		case core.ErrTokenExpired:
			// Even if expired, we'll consider logout successful
			c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
			return
		}

		c.JSON(statusCode, gin.H{"error": errorMsg})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

// Me returns information about the authenticated user
func (h *AuthHandlers) Me(c *gin.Context) {
	// User address is set by the auth middleware
	address, exists := c.Get("userAddress")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found in context"})
		return
	}

	// You could fetch additional user information from a database here
	// For now, we'll just return the address
	c.JSON(http.StatusOK, gin.H{
		"address": address,
	})
}

// Authorize checks if a user is authorized
func (h *AuthHandlers) Authorize(c *gin.Context) {
	// If the request reached this handler, it means the auth middleware
	// has already validated the token, so we can just return success

	// We can optionally include the user address from the context
	address, exists := c.Get("userAddress")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found in context"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authorized": true,
		"address":    address,
	})
}
