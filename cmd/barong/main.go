package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-redisstream/pkg/redisstream"
	"github.com/layer-3/barong"
	"github.com/layer-3/barong/internal/eth"
)

func main() {
	ctx := context.Background()
	logger := watermill.NewStdLogger(false, false)

	// Get Redis URL from environment
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379/0"
	}

	// Initialize Redis store
	store, err := barong.NewRedisStore(ctx, redisURL)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Initialize Watermill Redis publisher
	publisherConfig := redisstream.PublisherConfig{
		Client: store.GetClient(), // We'll need to expose this method in RedisStore
	}

	publisher, err := redisstream.NewPublisher(publisherConfig, logger)
	if err != nil {
		log.Fatalf("Failed to create Watermill publisher: %v", err)
	}
	defer publisher.Close()

	// Generate or load ES256 signing key
	// In a production environment, you would load this from a secure place
	privKey, _, err := eth.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create local signer with the key
	signer := eth.NewLocalSigner(privKey)

	// Register ES256 signer with JWT
	eth.RegisterES256Signer()

	// Create service
	service := barong.NewService(store, signer, publisher)

	// Create server
	server := &http.Server{
		Addr:    ":8080",
		Handler: service.Router(),
	}

	// Start server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Println("Server started on :8080")

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown the server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully")
}