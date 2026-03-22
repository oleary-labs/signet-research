package tss

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/fxamacker/cbor/v2"
)

// frostCommitPayload is the round-1 broadcast payload.
// Each signer broadcasts two nonce points (D_i = d_i*G, E_i = e_i*G).
type frostCommitPayload struct {
	D []byte `cbor:"d"` // 33-byte compressed nonce point D_i = d_i*G
	E []byte `cbor:"e"` // 33-byte compressed nonce point E_i = e_i*G
}

// frostPartialPayload is the round-2 broadcast payload (partial signature).
type frostPartialPayload struct {
	Z []byte `cbor:"z"` // 32-byte partial signature scalar z_i
}

// frostCommitRound is round 1 of FROST signing.
// Each signer generates two nonce scalars and broadcasts their public counterparts.
type frostCommitRound struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte

	mu            sync.Mutex
	d, e          *Scalar             // our nonce scalars (never revealed)
	D, E          *Point              // our nonce points D_i=d_i*G, E_i=e_i*G
	commits       map[PartyID][2]*Point // (D_j, E_j) from each signer
	broadcastSent bool
}

// Sign returns the starting Round for FROST threshold signing.
//
// Round 1: Each signer broadcasts nonce commitments (D_i, E_i).
// Round 2: Each signer computes binding factors, the combined nonce R,
//
//	the FROST challenge c, and broadcasts partial signature z_i.
//
// Local round 3: Aggregate z = Σ z_i, verify z*G = R + c*Y, return Signature.
//
// Signing equation: z_i = d_i + ρ_i·e_i + c·λ_i·x_i
// Combined:         z·G = R + c·Y   (standard Schnorr verification)
// Challenge:        c = keccak256(R_x || v || address(Y) || msgHash) mod N
func Sign(cfg *Config, signers []PartyID, messageHash []byte) Round {
	sorted := NewPartyIDSlice(signers)
	if len(sorted) < cfg.Threshold {
		return &errRound{err: fmt.Errorf("sign: insufficient signers: have %d, need %d", len(sorted), cfg.Threshold)}
	}
	if !sorted.Contains(cfg.ID) {
		return &errRound{err: fmt.Errorf("sign: self (%s) not in signer set", cfg.ID)}
	}
	return &frostCommitRound{
		cfg:         cfg,
		signers:     sorted,
		messageHash: messageHash,
		commits:     make(map[PartyID][2]*Point),
	}
}

func (r *frostCommitRound) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("sign round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("sign round1: unknown sender %s", msg.From)
	}
	if _, dup := r.commits[msg.From]; dup {
		return fmt.Errorf("sign round1: duplicate message from %s", msg.From)
	}
	var payload frostCommitPayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round1: unmarshal: %w", err)
	}
	D, err := PointFromSlice(payload.D)
	if err != nil {
		return fmt.Errorf("sign round1: parse D from %s: %w", msg.From, err)
	}
	E, err := PointFromSlice(payload.E)
	if err != nil {
		return fmt.Errorf("sign round1: parse E from %s: %w", msg.From, err)
	}
	r.commits[msg.From] = [2]*Point{D, E}
	return nil
}

func (r *frostCommitRound) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate nonce scalars on first call.
	if r.d == nil {
		var err error
		r.d, err = randomScalar()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round1: random nonce d: %w", err)
		}
		r.e, err = randomScalar()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round1: random nonce e: %w", err)
		}
		r.D = NewPoint().ScalarBaseMult(r.d)
		r.E = NewPoint().ScalarBaseMult(r.e)
		r.commits[r.cfg.ID] = [2]*Point{r.D, r.E}
	}

	var outMsgs []*Message
	if !r.broadcastSent {
		Db := r.D.Bytes()
		Eb := r.E.Bytes()
		data, err := cbor.Marshal(&frostCommitPayload{D: Db[:], E: Eb[:]})
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

	// Wait for all nonce commitments.
	if len(r.commits) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	// All commitments received. Compute binding factors and combined nonce.
	// ρ_j = SHA256(j || msgHash || B) where B = sorted(party_j || D_j || E_j)
	bindingFactors := make(map[PartyID]*Scalar, len(r.signers))
	for _, j := range r.signers {
		bindingFactors[j] = computeBindingFactor(j, r.messageHash, r.commits)
	}

	// R = Σ_j (D_j + ρ_j * E_j)
	R := NewPoint()
	for _, j := range r.signers {
		Dj := r.commits[j][0]
		Ej := r.commits[j][1]
		rhoJ := bindingFactors[j]
		R = R.Add(Dj.Add(Ej.ScalarMult(rhoJ)))
	}
	if R.IsIdentity() {
		return nil, nil, nil, fmt.Errorf("sign round1: combined nonce R is identity")
	}
	if R.XScalar().IsZero() {
		return nil, nil, nil, fmt.Errorf("sign round1: combined nonce R.x is zero")
	}

	// Challenge c = keccak256(R_x || v || address(Y) || msgHash) mod N
	c, err := computeChallenge(R, r.cfg.GroupKey, r.messageHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round1: challenge: %w", err)
	}
	if c.IsZero() {
		return nil, nil, nil, fmt.Errorf("sign round1: challenge is zero")
	}

	// Lagrange coefficient for self.
	lambda, err := LagrangeCoefficient([]PartyID(r.signers), r.cfg.ID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round1: lagrange: %w", err)
	}

	// Partial signature: z_i = d_i + ρ_i·e_i + c·λ_i·x_i
	rhoSelf := bindingFactors[r.cfg.ID]
	zi := r.d.Add(rhoSelf.Mul(r.e)).Add(c.Mul(lambda).Mul(r.cfg.Share))

	ziBytes := zi.Bytes()
	data, err := cbor.Marshal(&frostPartialPayload{Z: ziBytes[:]})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round1->2: marshal partial: %w", err)
	}
	outMsgs = append(outMsgs, &Message{
		From:      r.cfg.ID,
		To:        "",
		Round:     2,
		Broadcast: true,
		Data:      data,
	})

	round2 := &frostSignRound{
		cfg:      r.cfg,
		signers:  r.signers,
		R:        R,
		c:        c,
		partials: make(map[PartyID]*Scalar),
	}
	round2.partials[r.cfg.ID] = zi

	return outMsgs, round2, nil, nil
}

// computeBindingFactor computes ρ_id = SHA256(id || msgHash || sorted_B)
// where B is the sorted list of (party_j || D_j || E_j) for all signers.
func computeBindingFactor(id PartyID, msgHash []byte, commits map[PartyID][2]*Point) *Scalar {
	sorted := make([]PartyID, 0, len(commits))
	for pid := range commits {
		sorted = append(sorted, pid)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	h := sha256.New()
	h.Write([]byte(id))
	h.Write(msgHash)
	for _, pid := range sorted {
		h.Write([]byte(pid))
		Db := commits[pid][0].Bytes()
		Eb := commits[pid][1].Bytes()
		h.Write(Db[:])
		h.Write(Eb[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return ScalarFromBytes(digest)
}

// computeChallenge computes the FROST signing challenge.
// c = keccak256(R_x || R_y_parity || address(Y) || msgHash) mod N
// This matches the FROSTVerifier.sol challenge computation.
func computeChallenge(R *Point, groupKey []byte, msgHash []byte) (*Scalar, error) {
	Rb := R.Bytes()
	rx := Rb[1:]   // 32 bytes: x-coordinate of R
	v := Rb[0] - 2 // 0 if even y (0x02), 1 if odd y (0x03)

	groupPt, err := PointFromSlice(groupKey)
	if err != nil {
		return nil, fmt.Errorf("parse group key: %w", err)
	}
	signerAddr, err := ethereumAddressFromPoint(groupPt)
	if err != nil {
		return nil, fmt.Errorf("ethereum address: %w", err)
	}

	// input: R_x(32) || v(1) || signerAddr(20) || msgHash(32) = 85 bytes
	data := make([]byte, 0, 85)
	data = append(data, rx...)
	data = append(data, v)
	data = append(data, signerAddr[:]...)
	data = append(data, msgHash...)

	cRaw := ethcrypto.Keccak256(data)
	c := &Scalar{}
	c.s.SetByteSlice(cRaw)
	return c, nil
}

// frostSignRound aggregates partial signatures from all signers.
type frostSignRound struct {
	cfg     *Config
	signers PartyIDSlice
	R       *Point
	c       *Scalar

	mu       sync.Mutex
	partials map[PartyID]*Scalar
}

func (r *frostSignRound) Receive(msg *Message) error {
	if msg.Round != 2 || !msg.Broadcast {
		return fmt.Errorf("sign round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("sign round2: unknown sender %s", msg.From)
	}
	if _, dup := r.partials[msg.From]; dup {
		return fmt.Errorf("sign round2: duplicate message from %s", msg.From)
	}
	var payload frostPartialPayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round2: unmarshal: %w", err)
	}
	if len(payload.Z) != 32 {
		return fmt.Errorf("sign round2: invalid partial sig length %d", len(payload.Z))
	}
	var arr [32]byte
	copy(arr[:], payload.Z)
	r.partials[msg.From] = ScalarFromBytes(arr)
	return nil
}

func (r *frostSignRound) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.partials) < len(r.signers) {
		return nil, nil, nil, nil
	}

	// Aggregate: z = Σ z_j
	z := NewScalar()
	z.s.SetInt(0)
	for _, partial := range r.partials {
		z = z.Add(partial)
	}

	// Verify: z*G = R + c*Y
	Y, err := r.cfg.PublicKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round2: public key: %w", err)
	}

	lhs := NewPoint().ScalarBaseMult(z)
	cY := Y.ScalarMult(r.c)
	rhs := r.R.Add(cY)

	if !lhs.Equal(rhs) {
		return nil, nil, nil, fmt.Errorf("sign round2: FROST signature verification failed: z*G != R + c*Y")
	}

	Rb := r.R.Bytes()
	zb := z.Bytes()
	return nil, nil, &Signature{R: Rb, Z: zb}, nil
}
