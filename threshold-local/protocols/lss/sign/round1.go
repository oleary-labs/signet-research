package sign

import (
	"crypto/rand"
	"errors"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// round1 generates our nonce (k, K=g^k), broadcasts K, and collects N-1
// nonce commitments from the other signers before advancing to round2.
//
// Finalize is called by the handler immediately (after a 20ms sleep) because
// this is a BroadcastRound with no incoming P2P messages — hasAllMessages
// skips the broadcast check when our own broadcast hasn't been stored yet.
// We handle this by:
//
//  1. Generating k, K and sending the broadcast exactly once.
//  2. Returning self until receivedNonces contains all N entries.
//  3. On the final call, passing the complete nonces map to round2 so that
//     round2.Finalize never sees missing nonces.
type round1 struct {
	*round.Helper

	config      *config.Config
	signers     []party.ID
	messageHash []byte

	// Our nonce pair (generated once on first Finalize call)
	k curve.Scalar
	K curve.Point

	// Whether we have already sent the broadcast
	broadcastSent bool

	// Nonce commitments received from other signers (+ our own)
	receivedNonces sync.Map // map[party.ID]curve.Point
}

// broadcast1 contains the nonce commitment
type broadcast1 struct {
	round.NormalBroadcastContent

	// Public nonce commitment K = g^k, encoded as binary for CBOR compatibility
	KBytes []byte
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &broadcast1{}
}

// MessageContent implements round.Round — no P2P messages in round 1.
func (r *round1) MessageContent() round.Content {
	return nil
}

// RoundNumber implements round.Content
func (broadcast1) RoundNumber() round.Number {
	return 1
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(_ round.Message) error {
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound.
// Stores the nonce commitment K from another signer.
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if len(body.KBytes) == 0 {
		return errors.New("invalid nonce commitment: empty bytes")
	}

	K := r.Group().NewPoint()
	if err := K.UnmarshalBinary(body.KBytes); err != nil {
		return errors.New("invalid nonce commitment encoding")
	}
	if K.IsIdentity() {
		return errors.New("invalid nonce commitment: identity point")
	}

	// Verify sender is a signer
	isSigner := false
	for _, id := range r.signers {
		if id == from {
			isSigner = true
			break
		}
	}
	if !isSigner {
		return errors.New("sender not in signers list")
	}

	r.receivedNonces.Store(from, K)
	return nil
}

// Finalize implements round.Round.
//
// Phase 1 (first call, or any call before all N nonces are collected):
//   - Generate k, K once and send our broadcast once.
//   - Return self if receivedNonces has fewer than N entries.
//
// Phase 2 (all N nonces collected):
//   - Build the nonces map and return round2 with it.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// --- Phase 1a: generate nonce once ---
	if r.k == nil {
		r.k = sample.Scalar(rand.Reader, r.Group())
		r.K = r.k.ActOnBase()

		// Store our own nonce immediately so the count includes us.
		r.receivedNonces.Store(r.SelfID(), r.K)
	}

	// --- Phase 1b: send broadcast once ---
	if !r.broadcastSent {
		kBytes, err := r.K.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := r.BroadcastMessage(out, &broadcast1{KBytes: kBytes}); err != nil {
			return nil, err
		}
		r.broadcastSent = true
	}

	// --- Wait for all N nonces ---
	count := 0
	r.receivedNonces.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count < len(r.signers) {
		return r, nil
	}

	// --- Phase 2: all nonces collected — build map and return round2 ---
	nonces := make(map[party.ID]curve.Point, len(r.signers))
	r.receivedNonces.Range(func(key, value interface{}) bool {
		nonces[key.(party.ID)] = value.(curve.Point)
		return true
	})

	return &round2{
		round1: r,
		nonces: nonces,
	}, nil
}
