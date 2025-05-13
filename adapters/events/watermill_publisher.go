package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/layer-3/barong/ports"
)

// LogoutEvent represents a logout event
type LogoutEvent struct {
	Address string `json:"address"`
	TokenID string `json:"token_id"`
}

// WatermillPublisher implements the EventPublisher interface using Watermill
type WatermillPublisher struct {
	publisher message.Publisher
	topic     string
}

// NewWatermillPublisher creates a new Watermill publisher
func NewWatermillPublisher(publisher message.Publisher) ports.EventPublisher {
	return &WatermillPublisher{
		publisher: publisher,
		topic:     "barong.logout",
	}
}

// PublishLogout publishes a logout event
func (p *WatermillPublisher) PublishLogout(ctx context.Context, address string, tokenID string) error {
	event := LogoutEvent{
		Address: address,
		TokenID: tokenID,
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	msg := message.NewMessage(tokenID, payload)

	if err := p.publisher.Publish(p.topic, msg); err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	return nil
}
