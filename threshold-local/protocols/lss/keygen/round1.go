package keygen

import (
	"crypto/rand"
	"errors"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
)

// round1 generates a polynomial, broadcasts commitments, and (once all N-1
// commitment broadcasts have been received) sends P2P shares.
//
// Finalize is called by the handler with no message-count guard for BroadcastRound
// rounds that have no P2P messages (the "broadcasts[self]==nil skips the check"
// logic in hasAllMessages).  To handle this correctly Finalize:
//
//  1. Sends our commitment broadcast exactly once (first call).
//  2. Returns self until all N-1 other parties' broadcasts are stored (via
//     StoreBroadcastMessage).
//  3. On the final call (all N commitments present), sends P2P shares
//     (labelled RoundNumber=2 so the receiving handler buffers them for round2)
//     and returns round2.
//
// Round2 therefore always receives its full commitments map and has all N-1
// incoming P2P shares buffered before its own Finalize is ever called.
type round1 struct {
	*round.Helper

	// poly and chainKey are generated on the first Finalize call and reused.
	// Finalize is serialized by the handler (via finalized.LoadOrStore), so
	// plain (non-atomic) fields are safe here.
	poly          *polynomial.Polynomial
	chainKey      types.RID
	broadcastSent bool

	// commitments we compute for all parties once poly is known
	localCommitments map[party.ID]curve.Point

	// Storage for received broadcasts - using sync.Map for thread safety
	receivedCommitments sync.Map // map[party.ID]map[party.ID]curve.Point
	receivedChainKeys   sync.Map // map[party.ID]types.RID
}

// broadcast1 contains the polynomial commitments
type broadcast1 struct {
	round.NormalBroadcastContent

	// Commitments to polynomial - we commit to g^f(i) for each party i
	// Stored as binary data for CBOR compatibility
	Commitments map[party.ID][]byte

	// Chain key commitment
	ChainKey types.RID
}

// SetCommitments converts a map of points to binary for storage
func (b *broadcast1) SetCommitments(commitments map[party.ID]curve.Point) error {
	b.Commitments = make(map[party.ID][]byte)
	for id, point := range commitments {
		data, err := point.MarshalBinary()
		if err != nil {
			return err
		}
		b.Commitments[id] = data
	}
	return nil
}

// GetCommitments converts the binary data back to points
func (b *broadcast1) GetCommitments(group curve.Curve) (map[party.ID]curve.Point, error) {
	commitments := make(map[party.ID]curve.Point)
	for id, data := range b.Commitments {
		point := group.NewPoint()
		if err := point.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		commitments[id] = point
	}
	return commitments, nil
}

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &broadcast1{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// MessageContent implements round.Round — round1 has no incoming P2P messages.
func (r *round1) MessageContent() round.Content {
	return nil
}

// RoundNumber implements round.Content
func (broadcast1) RoundNumber() round.Number {
	return 1
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(_ round.Message) error {
	return nil // No P2P messages in round 1
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(_ round.Message) error {
	return nil // No P2P messages in round 1
}

// Finalize implements round.Round.
//
// Phase 1 (first call, or any call before all N-1 broadcasts arrive):
//   - Generate our polynomial and chain key (once).
//   - Send our commitment broadcast (once).
//   - Return self if fewer than N total entries are in receivedCommitments.
//
// Phase 2 (all N entries present):
//   - Collect all commitments.
//   - Send P2P shares to each other party as RoundNumber=2 messages (buffered
//     by the receiving handler until round2 activates).
//   - Return round2 with the full commitments map.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// --- Phase 1a: generate polynomial and chain key (once) ---
	if r.poly == nil {
		secret := sample.Scalar(rand.Reader, r.Group())
		r.poly = polynomial.NewPolynomial(r.Group(), r.Threshold()-1, secret)

		chainKey, err := types.NewRID(rand.Reader)
		if err != nil {
			return nil, err
		}
		r.chainKey = chainKey

		// Pre-compute commitments: g^f(j) for each party j.
		r.localCommitments = make(map[party.ID]curve.Point)
		for _, j := range r.PartyIDs() {
			x := j.Scalar(r.Group())
			share := r.poly.Evaluate(x)
			r.localCommitments[j] = share.ActOnBase()
		}

		// Store our own data so StoreBroadcastMessage won't overwrite it and
		// the count below includes us from the very first call.
		r.receivedCommitments.Store(r.SelfID(), r.localCommitments)
		r.receivedChainKeys.Store(r.SelfID(), r.chainKey)
	}

	// --- Phase 1b: send our commitment broadcast (once) ---
	if !r.broadcastSent {
		broadcast := &broadcast1{ChainKey: r.chainKey}
		if err := broadcast.SetCommitments(r.localCommitments); err != nil {
			return nil, err
		}
		if err := r.BroadcastMessage(out, broadcast); err != nil {
			return nil, err
		}
		r.broadcastSent = true
	}

	// --- Check: wait until all N-1 other parties' broadcasts have arrived ---
	count := 0
	r.receivedCommitments.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count < r.N() {
		// Not all broadcasts received yet; the handler will re-drive via
		// tryAdvanceRound when the next broadcast arrives.
		return r, nil
	}

	// --- Phase 2: all commitments collected — send P2P shares and advance ---
	allCommitments := make(map[party.ID]map[party.ID]curve.Point)
	allChainKeys := make(map[party.ID]types.RID)
	r.receivedCommitments.Range(func(key, value interface{}) bool {
		allCommitments[key.(party.ID)] = value.(map[party.ID]curve.Point)
		return true
	})
	r.receivedChainKeys.Range(func(key, value interface{}) bool {
		allChainKeys[key.(party.ID)] = value.(types.RID)
		return true
	})

	// Send P2P shares to each other party as round-2 messages.
	// The receiving handler buffers these until round2 activates, at which
	// point all inputs are immediately available.
	for _, j := range r.OtherPartyIDs() {
		x := j.Scalar(r.Group())
		share := r.poly.Evaluate(x)
		shareBytes, err := share.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := r.SendMessage(out, &message2{Share: shareBytes}, j); err != nil {
			return nil, err
		}
	}

	// Compute our own share f_self(self) to pass directly to round2.
	selfX := r.SelfID().Scalar(r.Group())
	selfShare := r.poly.Evaluate(selfX)

	return &round2{
		Helper:      r.Helper,
		commitments: allCommitments,
		chainKeys:   allChainKeys,
		selfShare:   selfShare,
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if len(body.Commitments) != r.N() {
		return errors.New("wrong number of commitments")
	}

	commitments, err := body.GetCommitments(r.Group())
	if err != nil {
		return err
	}

	r.receivedCommitments.Store(msg.From, commitments)
	r.receivedChainKeys.Store(msg.From, body.ChainKey)

	return nil
}
