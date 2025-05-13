package main

import (
	"log"
	"os"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-redisstream/pkg/redisstream"
	"github.com/layer-3/barong/adapters/events"
	"github.com/layer-3/barong/adapters/store"
	"github.com/layer-3/barong/adapters/tokenizer"
	"github.com/layer-3/barong/service"
	"github.com/layer-3/barong/transport/http"
	"github.com/redis/go-redis/v9"
)

func main() {
	// Generate a new ECDSA key pair (you would normally load this from somewhere secure)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Get Redis URL from environment
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379/0"
	}

	// Parse Redis URL and create client
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("Failed to parse Redis URL: %v", err)
	}

	redisClient := redis.NewClient(opts)

	// Initialize Watermill Redis publisher
	logger := watermill.NewStdLogger(false, false)
	publisher, err := redisstream.NewPublisher(
		redisstream.PublisherConfig{
			Client: redisClient,
		},
		logger,
	)
	if err != nil {
		log.Fatalf("Failed to create Redis publisher: %v", err)
	}

	tokenizer := tokenizer.NewJWTTokenizer(privateKey)
	store := store.NewRedisStore(redisClient)
	eventPub := events.NewWatermillPublisher(publisher)

	authService := service.NewAuthService(tokenizer, store, eventPub)

	// Setup Gin router
	router := http.SetupRouter(authService)

	// Start server
	if err := router.Run(":9000"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
