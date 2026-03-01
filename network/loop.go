package network

import (
	"github.com/luxfi/threshold/pkg/protocol"
)

// HandlerLoop connects a protocol.Handler to a SessionNetwork.
// It forwards outgoing messages from the handler to the network, and incoming
// messages from the network to the handler. It blocks until the handler's
// output channel is closed (protocol complete).
//
// This mirrors the pattern from test.HandlerLoop but uses the libp2p
// SessionNetwork instead of the in-memory test.Network.
func HandlerLoop(h *protocol.Handler, net *SessionNetwork) {
	// Drain outgoing messages in a separate goroutine. When h.Listen()
	// closes (protocol complete), close done to signal the receive loop.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range h.Listen() {
			net.Send(msg)
		}
	}()

	// Receive incoming messages until the protocol is done or the session closes.
	// The inner select guards against the race where done closes between the
	// outer select and the h.Accept() call.
	incoming := net.Next()
	for {
		select {
		case <-done:
			return
		case msg, ok := <-incoming:
			if !ok || msg == nil {
				return
			}
			select {
			case <-done:
				return
			default:
			}
			h.Accept(msg)
		}
	}
}
