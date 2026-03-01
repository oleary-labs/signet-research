package sign

import (
	"errors"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// round2 computes the combined nonce point R, generates a partial signature,
// broadcasts it, and collects N-1 partial signatures from the other signers.
// Once all N partial sigs are collected it passes the full set to round3.
//
// This follows the same "send once, return self until all arrive, then advance"
// pattern used in round1 for nonce collection.
type round2 struct {
	*round1

	// nonces is the complete map of public nonce commitments (N entries),
	// populated by round1 before creating round2.
	nonces map[party.ID]curve.Point

	// Computed once on first Finalize call.
	R          curve.Point  // combined nonce point
	rScalar    curve.Scalar // x-coordinate of R reduced mod q
	partialSig curve.Scalar // our partial signature s_i

	// Whether we have already sent the broadcast.
	broadcastSent bool

	// Partial signatures received from other signers (+ our own).
	receivedPartialSigs sync.Map // map[party.ID]curve.Scalar
}

// broadcast2 contains the partial signature
type broadcast2 struct {
	round.NormalBroadcastContent

	// Partial signature share s_i, encoded as binary for CBOR compatibility
	PartialSigBytes []byte
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{}
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return nil
}

// RoundNumber implements round.Content
func (broadcast2) RoundNumber() round.Number {
	return 2
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(_ round.Message) error {
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound.
// Stores the partial signature from another signer.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if len(body.PartialSigBytes) == 0 {
		return errors.New("nil partial signature")
	}

	sig := r.Group().NewScalar()
	if err := sig.UnmarshalBinary(body.PartialSigBytes); err != nil {
		return errors.New("invalid partial signature encoding")
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

	r.receivedPartialSigs.Store(from, sig)
	return nil
}

// Finalize implements round.Round.
//
// Phase 1 (first call, or any call before all N partial sigs are collected):
//   - Compute R and our partial sig once.
//   - Send our broadcast once.
//   - Return self if receivedPartialSigs has fewer than N entries.
//
// Phase 2 (all N partial sigs collected):
//   - Build the partialSigs map and return round3 with it.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// --- Phase 1a: compute R and partial sig once ---
	if r.partialSig == nil {
		// Compute combined R = sum of all K values
		r.R = r.Group().NewPoint()
		for _, K := range r.nonces {
			r.R = r.R.Add(K)
		}

		// Extract x-coordinate of R as a scalar (mod q)
		r.rScalar = r.R.XScalar()

		// Convert message hash to scalar
		mScalar := curve.FromHash(r.Group(), r.messageHash)

		// Lagrange coefficient for our share
		lagrangeCoeff := polynomial.Lagrange(r.Group(), r.signers)[r.SelfID()]

		// Compute partial sig: s_i = k_i + r * λ_i * x_i * m
		partialSig := r.Group().NewScalar()
		partialSig = partialSig.Set(r.rScalar)       // r
		partialSig = partialSig.Mul(lagrangeCoeff)   // r * λ_i
		partialSig = partialSig.Mul(r.config.ECDSA)  // r * λ_i * x_i
		partialSig = partialSig.Mul(mScalar)         // r * λ_i * x_i * m
		partialSig = partialSig.Add(r.k)             // k_i + r * λ_i * x_i * m
		r.partialSig = partialSig

		// Store our own partial sig immediately
		r.receivedPartialSigs.Store(r.SelfID(), r.partialSig)
	}

	// --- Phase 1b: send broadcast once ---
	if !r.broadcastSent {
		sigBytes, err := r.partialSig.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := r.BroadcastMessage(out, &broadcast2{PartialSigBytes: sigBytes}); err != nil {
			return nil, err
		}
		r.broadcastSent = true
	}

	// --- Wait for all N partial sigs ---
	count := 0
	r.receivedPartialSigs.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count < len(r.signers) {
		return r, nil
	}

	// --- Phase 2: all partial sigs collected — build map and return round3 ---
	partialSigs := make(map[party.ID]curve.Scalar, len(r.signers))
	r.receivedPartialSigs.Range(func(key, value interface{}) bool {
		partialSigs[key.(party.ID)] = value.(curve.Scalar)
		return true
	})

	return &round3{
		round2:      r,
		partialSigs: partialSigs,
		rScalar:     r.rScalar,
	}, nil
}
