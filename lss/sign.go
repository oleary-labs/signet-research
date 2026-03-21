package lss

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// Signature is the output of a threshold signing session.
type Signature struct {
	R [33]byte // compressed nonce point
	S [32]byte // combined partial signature scalar
}

// SigEthereum returns a 65-byte Ethereum-compatible signature: r(32) || s(32) || v(1).
// r is the x-coordinate of R, v is the recovery bit derived from R's y-coordinate parity.
func (sig *Signature) SigEthereum() ([]byte, error) {
	// Parse R from compressed form to get x-coordinate and y parity.
	Rpt, err := PointFromBytes(sig.R)
	if err != nil {
		return nil, fmt.Errorf("parse R: %w", err)
	}
	rScalar := Rpt.XScalar()
	rBytes := rScalar.Bytes()
	sBytes := sig.S

	// Recovery bit: 0 if R.Y is even, 1 if odd.
	// The compressed encoding: 0x02 = even Y, 0x03 = odd Y.
	v := byte(0)
	if sig.R[0] == 0x03 {
		v = 1
	}

	out := make([]byte, 65)
	copy(out[:32], rBytes[:])
	copy(out[32:64], sBytes[:])
	out[64] = v
	return out, nil
}

// sign1Payload is the round-1 broadcast payload (nonce point).
type sign1Payload struct {
	K []byte `cbor:"k"` // 33-byte compressed nonce point K = k*G
}

// sign2Payload is the round-2 broadcast payload (partial signature).
type sign2Payload struct {
	S []byte `cbor:"s"` // 32-byte partial signature scalar
}

// signRound1 broadcasts each party's nonce point K = k*G.
type signRound1 struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte

	mu            sync.Mutex
	nonce         *Scalar  // our k
	noncePoint    *Point   // our K = k*G
	nonces        map[PartyID]*Point // received nonce points
	broadcastSent bool
}

// Sign returns the starting Round for threshold signing.
func Sign(cfg *Config, signers []PartyID, messageHash []byte) Round {
	return &signRound1{
		cfg:         cfg,
		signers:     NewPartyIDSlice(signers),
		messageHash: messageHash,
		nonces:      make(map[PartyID]*Point),
	}
}

func (r *signRound1) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("sign round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	var payload sign1Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round1: unmarshal: %w", err)
	}
	pt, err := PointFromSlice(payload.K)
	if err != nil {
		return fmt.Errorf("sign round1: parse nonce point from %s: %w", msg.From, err)
	}
	r.mu.Lock()
	r.nonces[msg.From] = pt
	r.mu.Unlock()
	return nil
}

func (r *signRound1) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate nonce on first call.
	if r.nonce == nil {
		var kb [32]byte
		if _, err := rand.Read(kb[:]); err != nil {
			return nil, nil, nil, fmt.Errorf("sign round1: random nonce: %w", err)
		}
		r.nonce = ScalarFromBytes(kb)
		// Ensure non-zero.
		for r.nonce.IsZero() {
			rand.Read(kb[:])
			r.nonce = ScalarFromBytes(kb)
		}
		r.noncePoint = NewPoint().ScalarBaseMult(r.nonce)

		// Store our own nonce point.
		r.nonces[r.cfg.ID] = r.noncePoint
	}

	var outMsgs []*Message
	if !r.broadcastSent {
		Kb := r.noncePoint.Bytes()
		data, err := cbor.Marshal(&sign1Payload{K: Kb[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round1: marshal: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.cfg.ID,
			To:        "",
			Round:     1,
			Broadcast: true,
			Data:      data,
		})
		r.broadcastSent = true
	}

	// Wait for all N nonce points.
	if len(r.nonces) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	return outMsgs, &signRound2{
		cfg:         r.cfg,
		signers:     r.signers,
		messageHash: r.messageHash,
		nonce:       r.nonce,
		nonces:      r.nonces,
		partials:    make(map[PartyID]*Scalar),
	}, nil, nil
}

// signRound2 computes and broadcasts partial signatures.
type signRound2 struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte
	nonce       *Scalar
	nonces      map[PartyID]*Point

	mu            sync.Mutex
	partials      map[PartyID]*Scalar
	broadcastSent bool
	R             *Point // combined nonce point
	r             *Scalar // x-coordinate of R
}

func (r *signRound2) Receive(msg *Message) error {
	if msg.Round != 2 || !msg.Broadcast {
		return fmt.Errorf("sign round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	var payload sign2Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round2: unmarshal: %w", err)
	}
	if len(payload.S) != 32 {
		return fmt.Errorf("sign round2: invalid partial sig length %d", len(payload.S))
	}
	var arr [32]byte
	copy(arr[:], payload.S)
	partial := ScalarFromBytes(arr)

	r.mu.Lock()
	r.partials[msg.From] = partial
	r.mu.Unlock()
	return nil
}

func (r *signRound2) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Compute R and r on first call.
	if r.R == nil {
		// R = Σ K_i
		R := NewPoint()
		for _, K := range r.nonces {
			R = R.Add(K)
		}
		r.R = R
		r.r = R.XScalar()
	}

	// Compute and broadcast our partial signature once.
	var outMsgs []*Message
	if !r.broadcastSent {
		m := ScalarFromHash(r.messageHash)
		lambda, err := LagrangeCoefficient([]PartyID(r.signers), r.cfg.ID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round2: lagrange: %w", err)
		}

		// partial = k + r * λ * x * m
		partialSig := r.nonce.Add(
			r.r.Mul(lambda).Mul(r.cfg.Share).Mul(m),
		)

		// Store our own partial.
		r.partials[r.cfg.ID] = partialSig

		sBytes := partialSig.Bytes()
		data, err := cbor.Marshal(&sign2Payload{S: sBytes[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round2: marshal: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.cfg.ID,
			To:        "",
			Round:     2,
			Broadcast: true,
			Data:      data,
		})
		r.broadcastSent = true
	}

	// Wait for all N partial signatures.
	if len(r.partials) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	return outMsgs, &signRound3{
		cfg:         r.cfg,
		signers:     r.signers,
		messageHash: r.messageHash,
		R:           r.R,
		r:           r.r,
		partials:    r.partials,
	}, nil, nil
}

// signRound3 combines partial signatures and verifies.
type signRound3 struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte
	R           *Point
	r           *Scalar
	partials    map[PartyID]*Scalar
}

func (r *signRound3) Receive(msg *Message) error {
	return fmt.Errorf("sign round3: no messages expected")
}

func (r *signRound3) Finalize() ([]*Message, Round, interface{}, error) {
	// s = Σ s_i
	s := NewScalar()
	s.s.SetInt(0)
	for _, partial := range r.partials {
		s = s.Add(partial)
	}

	// Verify: s*G == R + r*m*X
	pubKey, err := r.cfg.PublicKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round3: public key: %w", err)
	}

	m := ScalarFromHash(r.messageHash)
	// LHS: s*G
	lhs := NewPoint().ScalarBaseMult(s)
	// RHS: R + r*m*X
	rmX := pubKey.ScalarMult(r.r.Mul(m))
	rhs := r.R.Add(rmX)

	if !lhs.Equal(rhs) {
		return nil, nil, nil, fmt.Errorf("sign round3: signature verification failed: s*G != R + r*m*X")
	}

	Rb := r.R.Bytes()
	sb := s.Bytes()

	sig := &Signature{
		R: Rb,
		S: sb,
	}

	return nil, nil, sig, nil
}

