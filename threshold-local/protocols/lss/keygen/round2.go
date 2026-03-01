package keygen

import (
	"errors"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// round2 receives P2P shares sent by all parties during round 1's Finalize.
// By the time the handler activates round2, all N-1 incoming shares are already
// buffered (they were sent as RoundNumber=2 messages during round 1), so Finalize
// is called exactly once with all data present and returns round3 immediately.
type round2 struct {
	*round.Helper

	// selfShare is f_self(self), pre-computed in round 1 so we don't need poly here.
	selfShare curve.Scalar

	// Commitments from all parties: commitments[i][j] = g^f_i(j)
	commitments map[party.ID]map[party.ID]curve.Point

	// Chain keys from all parties
	chainKeys map[party.ID]types.RID

	// Shares we receive from other parties via StoreMessage
	shares sync.Map // map[party.ID]curve.Scalar
}

// message2 contains the secret share for a party
type message2 struct {
	// Share encoded as binary for CBOR compatibility
	Share []byte
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return &message2{}
}

// RoundNumber implements round.Content
func (message2) RoundNumber() round.Number {
	return 2
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if to != r.SelfID() {
		return errors.New("message not for us")
	}

	// Unmarshal the share
	share := r.Group().NewScalar()
	if err := share.UnmarshalBinary(body.Share); err != nil {
		return errors.New("invalid share encoding")
	}

	// Verify share against commitment: check g^share == commitments[from][self]
	commitments, ok := r.commitments[from]
	if !ok {
		return errors.New("missing commitments from sender")
	}

	expectedCommitment, ok := commitments[to]
	if !ok {
		return errors.New("missing commitment for our ID")
	}

	sharePoint := share.ActOnBase()
	if !sharePoint.Equal(expectedCommitment) {
		return errors.New("share doesn't match commitment")
	}

	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	body := msg.Content.(*message2)

	share := r.Group().NewScalar()
	if err := share.UnmarshalBinary(body.Share); err != nil {
		return errors.New("invalid share encoding")
	}

	r.shares.Store(msg.From, share)
	return nil
}

// Finalize implements round.Round.
// Called once all N-1 round-2 P2P messages have been received by the handler.
// Combines the received shares with our own self share and advances to round3.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	shares := make(map[party.ID]curve.Scalar, r.N())

	// Add our own share (pre-computed in round1).
	shares[r.SelfID()] = r.selfShare

	// Collect shares from the other N-1 parties (already stored by StoreMessage).
	r.shares.Range(func(key, value interface{}) bool {
		shares[key.(party.ID)] = value.(curve.Scalar)
		return true
	})

	if len(shares) != r.N() {
		return nil, errors.New("round2 finalize: missing shares")
	}

	return &round3{
		Helper:      r.Helper,
		commitments: r.commitments,
		chainKeys:   r.chainKeys,
		shares:      shares,
	}, nil
}
