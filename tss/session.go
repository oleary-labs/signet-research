package tss

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

// errRound is a sentinel round that returns an error immediately.
type errRound struct{ err error }

func (r *errRound) Receive(msg *Message) error                          { return r.err }
func (r *errRound) Finalize() ([]*Message, Round, interface{}, error) {
	return nil, nil, nil, r.err
}

// Run drives a protocol session to completion.
// It calls Finalize() in a loop, sending outgoing messages via net,
// delivering incoming messages to the current round via Receive().
//
// Messages that arrive early (e.g. round-2 shares received while still in
// round-1) are buffered and replayed automatically on each round transition.
func Run(ctx context.Context, start Round, net Network) (interface{}, error) {
	current := start
	incoming := net.Incoming()
	var pending []*Message // messages buffered for a future round

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		out, next, result, err := current.Finalize()
		if err != nil {
			return nil, fmt.Errorf("finalize: %w", err)
		}

		for _, msg := range out {
			net.Send(msg)
		}

		if result != nil {
			return result, nil
		}

		if next != nil {
			current = next
			// Drain buffered messages into the new round.
			var stillPending []*Message
			for _, msg := range pending {
				if err := current.Receive(msg); err != nil {
					stillPending = append(stillPending, msg)
				}
			}
			pending = stillPending
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
				// Buffer for a future round transition.
				pending = append(pending, msg)
			}
		}
	}
}
