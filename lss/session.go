package lss

import (
	"context"
	"fmt"
)

// Round is the interface each protocol round implements.
type Round interface {
	// Receive delivers an incoming message (broadcast or unicast).
	Receive(msg *Message) error

	// Finalize attempts to advance the round.
	// Returns: outgoing messages to send, next round (nil=stay, non-nil=advance),
	// final result (non-nil=protocol complete), error.
	Finalize() (out []*Message, next Round, result interface{}, err error)
}

// Run drives a protocol session to completion.
// It calls Finalize() in a loop, sending outgoing messages via net,
// delivering incoming messages to the current round via Receive().
func Run(ctx context.Context, start Round, net Network) (interface{}, error) {
	current := start
	incoming := net.Incoming()

	for {
		// Check context before trying to finalize.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		out, next, result, err := current.Finalize()
		if err != nil {
			return nil, fmt.Errorf("finalize: %w", err)
		}

		// Send outgoing messages.
		for _, msg := range out {
			net.Send(msg)
		}

		// Protocol complete.
		if result != nil {
			return result, nil
		}

		if next != nil {
			// Advance to the next round immediately.
			current = next
			continue
		}

		// Same round — wait for an incoming message.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg, ok := <-incoming:
			if !ok {
				return nil, fmt.Errorf("incoming channel closed")
			}
			if msg == nil {
				continue
			}
			if err := current.Receive(msg); err != nil {
				// Log and skip invalid messages; don't abort the session.
				_ = err
				continue
			}
		}
	}
}
