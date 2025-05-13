package http

import (
	"github.com/gin-gonic/gin"
	"github.com/layer-3/barong/service"
)

// SetupRouter sets up the Gin router
func SetupRouter(authService *service.AuthService) *gin.Engine {
	router := gin.Default()

	// Create handlers
	handlers := NewAuthHandlers(authService)

	// Auth routes
	auth := router.Group("/auth")
	{
		auth.POST("/challenge", handlers.Challenge)
		auth.POST("/login", handlers.Login)
		auth.POST("/refresh", handlers.Refresh)
		auth.POST("/logout", handlers.Logout)
	}

	// Protected API routes
	api := router.Group("/api")
	api.Use(AuthMiddleware(authService))
	{
		api.GET("/me", handlers.Me)
		api.GET("/authorize", handlers.Authorize)
	}

	return router
}
