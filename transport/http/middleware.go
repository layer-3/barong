package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/layer-3/barong/core"
	"github.com/layer-3/barong/service"
)

// AuthMiddleware creates middleware that validates access tokens
func AuthMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")

		// Check if the Authorization header is present and in correct format
		if len(auth) < 8 || auth[:7] != "Bearer " {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
			return
		}

		// Extract the token
		token := auth[7:]

		// Validate the token
		session, err := authService.ValidateAccessToken(c.Request.Context(), token)
		if err != nil {
			if err == core.ErrTokenExpired {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			}
			return
		}

		// Set the user address in the context
		c.Set("userAddress", session.Address)

		c.Next()
	}
}
