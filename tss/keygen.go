package tss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// frostKeygen1Payload is the round-1 broadcast payload.
// Contains Feldman VSS coefficient commitments C_k = a_k * G for k=0..t-1,
// plus a random chain key contribution.
type frostKeygen1Payload struct {
	Coeffs   [][]byte `cbor:"c"` // t compressed points (33 bytes each)
	ChainKey []byte   `cbor:"k"` // 32-byte random chain key contribution
}

// frostKeygen2Payload is the round-2 unicast payload (share delivery).
type frostKeygen2Payload struct {
	Share []byte `cbor:"s"` // 32-byte scalar f_i(x_j)
}

// keygenRound1 is the first round of Feldman VSS key generation.
type keygenRound1 struct {
	self      PartyID
	parties   PartyIDSlice
	threshold int

	mu            sync.Mutex
	poly          *Polynomial
	chainKey      []byte
	broadcasts    map[PartyID]*frostKeygen1Payload
	broadcastSent bool
}

// Keygen returns the starting Round for distributed FROST key generation.
// Uses Feldman VSS with coefficient commitments.
func Keygen(selfID PartyID, participants []PartyID, threshold int) Round {
	return &keygenRound1{
		self:       selfID,
		parties:    NewPartyIDSlice(participants),
		threshold:  threshold,
		broadcasts: make(map[PartyID]*frostKeygen1Payload),
	}
}

func (r *keygenRound1) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("keygen round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.parties.Contains(msg.From) {
		return fmt.Errorf("keygen round1: unknown sender %s", msg.From)
	}
	if _, dup := r.broadcasts[msg.From]; dup {
		return fmt.Errorf("keygen round1: duplicate message from %s", msg.From)
	}
	var payload frostKeygen1Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("keygen round1: unmarshal: %w", err)
	}
	if len(payload.Coeffs) != r.threshold {
		return fmt.Errorf("keygen round1: expected %d coefficient commitments, got %d from %s",
			r.threshold, len(payload.Coeffs), msg.From)
	}
	r.broadcasts[msg.From] = &payload
	return nil
}

func (r *keygenRound1) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate polynomial and commitments on first call.
	if r.poly == nil {
		secret, err := randomScalar()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: random secret: %w", err)
		}
		poly, err := NewPolynomial(r.threshold, secret)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: polynomial: %w", err)
		}
		r.poly = poly

		var ck [32]byte
		if _, err := rand.Read(ck[:]); err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: chain key: %w", err)
		}
		r.chainKey = ck[:]

		// Compute Feldman coefficient commitments: C_k = a_k * G
		coeffs := poly.Coefficients()
		coeffCommits := make([][]byte, len(coeffs))
		for k, ak := range coeffs {
			Ck := NewPoint().ScalarBaseMult(ak)
			b := Ck.Bytes()
			coeffCommits[k] = b[:]
		}

		r.broadcasts[r.self] = &frostKeygen1Payload{
			Coeffs:   coeffCommits,
			ChainKey: r.chainKey,
		}
	}

	var outMsgs []*Message
	if !r.broadcastSent {
		own := r.broadcasts[r.self]
		data, err := cbor.Marshal(own)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: marshal: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.self,
			To:        "",
			Round:     1,
			Broadcast: true,
			Data:      data,
		})
		r.broadcastSent = true
	}

	// Wait until all N broadcasts received.
	if len(r.broadcasts) < len(r.parties) {
		return outMsgs, nil, nil, nil
	}

	// Send unicast shares to each other party.
	for _, j := range r.parties {
		if j == r.self {
			continue
		}
		xj := j.Scalar()
		shareVal := r.poly.Evaluate(xj)
		shareBytes := shareVal.Bytes()

		data, err := cbor.Marshal(&frostKeygen2Payload{Share: shareBytes[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1->2: marshal share: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.self,
			To:        j,
			Round:     2,
			Broadcast: false,
			Data:      data,
		})
	}

	// Compute own share from own polynomial.
	xSelf := r.self.Scalar()
	ownShare := r.poly.Evaluate(xSelf)

	round2 := &keygenRound2{
		self:         r.self,
		parties:      r.parties,
		threshold:    r.threshold,
		broadcastsR1: r.broadcasts,
		shares:       make(map[PartyID]*Scalar),
	}
	round2.shares[r.self] = ownShare

	return outMsgs, round2, nil, nil
}

// keygenRound2 collects unicast shares from other parties and verifies them.
type keygenRound2 struct {
	self         PartyID
	parties      PartyIDSlice
	threshold    int
	broadcastsR1 map[PartyID]*frostKeygen1Payload

	mu     sync.Mutex
	shares map[PartyID]*Scalar
}

func (r *keygenRound2) Receive(msg *Message) error {
	if msg.Round != 2 || msg.Broadcast {
		return fmt.Errorf("keygen round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	if msg.To != r.self {
		return fmt.Errorf("keygen round2: message not for us")
	}
	if !r.parties.Contains(msg.From) {
		return fmt.Errorf("keygen round2: unknown sender %s", msg.From)
	}
	r.mu.Lock()
	if _, dup := r.shares[msg.From]; dup {
		r.mu.Unlock()
		return fmt.Errorf("keygen round2: duplicate share from %s", msg.From)
	}
	r.mu.Unlock()

	var payload frostKeygen2Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("keygen round2: unmarshal: %w", err)
	}
	if len(payload.Share) != 32 {
		return fmt.Errorf("keygen round2: invalid share length %d", len(payload.Share))
	}

	// Verify share against sender's Feldman commitments.
	senderBC, ok := r.broadcastsR1[msg.From]
	if !ok {
		return fmt.Errorf("keygen round2: no round1 broadcast from %s", msg.From)
	}

	var shareArr [32]byte
	copy(shareArr[:], payload.Share)
	share := ScalarFromBytes(shareArr)

	if err := verifyFeldmanShare(share, r.self.Scalar(), senderBC.Coeffs); err != nil {
		return fmt.Errorf("keygen round2: Feldman verification failed from %s: %w", msg.From, err)
	}

	r.mu.Lock()
	r.shares[msg.From] = share
	r.mu.Unlock()
	return nil
}

// verifyFeldmanShare verifies that share * G == Σ_k C_k * x^k.
func verifyFeldmanShare(share *Scalar, x *Scalar, coeffCommits [][]byte) error {
	// Compute expected point: Σ_{k=0}^{t-1} C_k * x^k
	expected := NewPoint()
	xPow := NewScalar()
	xPow.s.SetInt(1)

	for _, ckBytes := range coeffCommits {
		Ck, err := PointFromSlice(ckBytes)
		if err != nil {
			return fmt.Errorf("parse commitment: %w", err)
		}
		term := Ck.ScalarMult(xPow)
		expected = expected.Add(term)
		xPow = xPow.Mul(x)
	}

	check := NewPoint().ScalarBaseMult(share)
	if !check.Equal(expected) {
		return fmt.Errorf("share does not match Feldman commitment")
	}
	return nil
}

func (r *keygenRound2) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.shares) < len(r.parties) {
		return nil, nil, nil, nil
	}

	return nil, &keygenRound3{
		self:         r.self,
		parties:      r.parties,
		threshold:    r.threshold,
		broadcastsR1: r.broadcastsR1,
		shares:       r.shares,
	}, nil, nil
}

// keygenRound3 finalizes the keygen (no messages — local computation only).
type keygenRound3 struct {
	self         PartyID
	parties      PartyIDSlice
	threshold    int
	broadcastsR1 map[PartyID]*frostKeygen1Payload
	shares       map[PartyID]*Scalar
}

func (r *keygenRound3) Receive(msg *Message) error {
	return fmt.Errorf("keygen round3: no messages expected")
}

func (r *keygenRound3) Finalize() ([]*Message, Round, interface{}, error) {
	// Sum all shares: x_self = Σ_i f_i(x_self)
	myShare := NewScalar()
	myShare.s.SetInt(0)
	for _, share := range r.shares {
		myShare = myShare.Add(share)
	}

	// Compute group public key: Y = Σ_i C_{i,0} (sum of all parties' constant-term commitments)
	groupKey := NewPoint()
	for _, p := range r.parties {
		bc, ok := r.broadcastsR1[p]
		if !ok {
			return nil, nil, nil, fmt.Errorf("keygen round3: missing broadcast from %s", p)
		}
		C0, err := PointFromSlice(bc.Coeffs[0])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round3: parse C0 from %s: %w", p, err)
		}
		groupKey = groupKey.Add(C0)
	}
	groupKeyBytes := groupKey.Bytes()

	// Combine chain keys: SHA256(ck_1 || ... || ck_N) in sorted party order.
	h := sha256.New()
	for _, p := range r.parties {
		bc := r.broadcastsR1[p]
		h.Write(bc.ChainKey)
	}
	combinedChainKey := h.Sum(nil)
	rid := sha256.Sum256(combinedChainKey)

	cfg := &Config{
		ID:         r.self,
		Threshold:  r.threshold,
		Generation: 0,
		Share:      myShare,
		GroupKey:   groupKeyBytes[:],
		Parties:    []PartyID(r.parties),
		ChainKey:   combinedChainKey,
		RID:        rid[:],
	}

	return nil, nil, cfg, nil
}
