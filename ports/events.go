package ports

import "context"

// EventPublisher publishes events to notify other instances
type EventPublisher interface {
	PublishLogout(ctx context.Context, address string, tokenID string) error
}
