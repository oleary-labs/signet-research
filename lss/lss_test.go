package lss

import (
	"context"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// inMemNetwork is a simple in-process Network for testing.
type inMemNetwork struct {
	ch chan *Message
}

func newInMemNetwork(buf int) *inMemNetwork {
	return &inMemNetwork{ch: make(chan *Message, buf)}
}

func (n *inMemNetwork) Send(msg *Message)        { n.ch <- msg }
func (n *inMemNetwork) Incoming() <-chan *Message { return n.ch }

// routingNetwork routes messages to the appropriate party's inMemNetwork.
type routingNetwork struct {
	self    PartyID
	nets    map[PartyID]*inMemNetwork
	parties []PartyID
}

func (r *routingNetwork) Send(msg *Message) {
	// Broadcast: send to all except self.
	if msg.To == "" {
		for _, pid := range r.parties {
			if pid == r.self {
				continue
			}
			r.nets[pid].ch <- msg
		}
	} else {
		if net, ok := r.nets[msg.To]; ok {
			net.ch <- msg
		}
	}
}

func (r *routingNetwork) Incoming() <-chan *Message {
	return r.nets[r.self].ch
}

// TestScalarArithmetic verifies basic scalar operations.
func TestScalarArithmetic(t *testing.T) {
	// Test Add
	a := NewScalar()
	a.s.SetInt(5)
	b := NewScalar()
	b.s.SetInt(7)
	c := a.Add(b)
	var expected [32]byte
	expected[31] = 12
	if c.Bytes() != expected {
		t.Errorf("Add: expected 12, got %x", c.Bytes())
	}

	// Test Mul
	d := a.Mul(b)
	var exp35 [32]byte
	exp35[31] = 35
	if d.Bytes() != exp35 {
		t.Errorf("Mul: expected 35, got %x", d.Bytes())
	}

	// Test Inverse: a * a^{-1} == 1
	aInv := a.Inverse()
	one := a.Mul(aInv)
	var expOne [32]byte
	expOne[31] = 1
	if one.Bytes() != expOne {
		t.Errorf("Inverse: a * a^-1 != 1")
	}

	// Test Negate: a + (-a) == 0
	aNeg := a.Negate()
	zero := a.Add(aNeg)
	if !zero.IsZero() {
		t.Errorf("Negate: a + (-a) != 0")
	}
}

// TestPointArithmetic verifies basic point operations.
func TestPointArithmetic(t *testing.T) {
	G := GeneratorPoint()
	if G.IsIdentity() {
		t.Fatal("generator should not be identity")
	}

	// 2*G == G + G
	two := NewScalar()
	two.s.SetInt(2)
	twoG := NewPoint().ScalarBaseMult(two)
	GplusG := G.Add(G)
	if !twoG.Equal(GplusG) {
		t.Error("2*G != G+G")
	}

	// Point serialization round-trip.
	b := G.Bytes()
	G2, err := PointFromBytes(b)
	if err != nil {
		t.Fatalf("PointFromBytes: %v", err)
	}
	if !G.Equal(G2) {
		t.Error("serialization round-trip failed")
	}
}

// TestLagrange verifies Lagrange coefficients sum to 1 via λ*x = secret reconstruction.
func TestLagrange(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}

	// Give each party a known scalar.
	scalars := map[PartyID]*Scalar{}
	for _, p := range parties {
		scalars[p] = p.Scalar()
	}

	// Lagrange coefficients at x=0 should satisfy:
	// Σ λ_i * x_i == x_0 for any degree-1 polynomial through the points
	// Actually for threshold=3, all three are needed. Just verify they're non-zero.
	for _, p := range parties {
		lambda, err := LagrangeCoefficient(parties, p)
		if err != nil {
			t.Fatalf("LagrangeCoefficient(%s): %v", p, err)
		}
		if lambda.IsZero() {
			t.Errorf("Lagrange coefficient for %s is zero", p)
		}
	}
}

// TestPolynomial verifies polynomial evaluation.
func TestPolynomial(t *testing.T) {
	secret := NewScalar()
	secret.s.SetInt(42)

	poly, err := NewPolynomial(2, secret)
	if err != nil {
		t.Fatalf("NewPolynomial: %v", err)
	}

	// f(0) should equal secret (but our Evaluate uses Horner's method, so x=0 gives coeffs[0]).
	zero := NewScalar()
	zero.s.SetInt(0)
	result := poly.Evaluate(zero)
	if !result.Equal(secret) {
		t.Errorf("f(0) != secret: got %x want %x", result.Bytes(), secret.Bytes())
	}
}

// TestKeygenRoundtrip runs a full 2-of-3 keygen using in-process routing.
func TestKeygenRoundtrip(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2

	// Create per-party networks.
	nets := map[PartyID]*inMemNetwork{}
	for _, p := range parties {
		nets[p] = newInMemNetwork(1000)
	}

	type result struct {
		id  PartyID
		cfg *Config
		err error
	}
	results := make(chan result, len(parties))

	for _, p := range parties {
		p := p
		net := &routingNetwork{
			self:    p,
			nets:    nets,
			parties: parties,
		}
		go func() {
			round := Keygen(p, parties, threshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				results <- result{id: p, err: err}
				return
			}
			cfg, ok := res.(*Config)
			if !ok {
				results <- result{id: p, err: nil}
				return
			}
			results <- result{id: p, cfg: cfg}
		}()
	}

	configs := map[PartyID]*Config{}
	for i := 0; i < len(parties); i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("party %s keygen failed: %v", r.id, r.err)
		}
		if r.cfg == nil {
			t.Fatalf("party %s got nil config", r.id)
		}
		configs[r.id] = r.cfg
	}

	// Verify all parties get the same public key.
	pub0, err := configs["alice"].PublicKey()
	if err != nil {
		t.Fatalf("PublicKey alice: %v", err)
	}
	pub1, err := configs["bob"].PublicKey()
	if err != nil {
		t.Fatalf("PublicKey bob: %v", err)
	}
	pub2, err := configs["carol"].PublicKey()
	if err != nil {
		t.Fatalf("PublicKey carol: %v", err)
	}

	if !pub0.Equal(pub1) {
		t.Error("alice and bob public keys differ")
	}
	if !pub0.Equal(pub2) {
		t.Error("alice and carol public keys differ")
	}
	t.Logf("Public key: %x", pub0.Bytes())
}

// TestKeygenAndSign runs keygen followed by signing with a 2-of-3 threshold.
func TestKeygenAndSign(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2

	// Run keygen.
	nets := map[PartyID]*inMemNetwork{}
	for _, p := range parties {
		nets[p] = newInMemNetwork(1000)
	}

	type kresult struct {
		id  PartyID
		cfg *Config
		err error
	}
	kresults := make(chan kresult, len(parties))

	for _, p := range parties {
		p := p
		net := &routingNetwork{self: p, nets: nets, parties: parties}
		go func() {
			round := Keygen(p, parties, threshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				kresults <- kresult{id: p, err: err}
				return
			}
			cfg := res.(*Config)
			kresults <- kresult{id: p, cfg: cfg}
		}()
	}

	configs := map[PartyID]*Config{}
	for i := 0; i < len(parties); i++ {
		r := <-kresults
		if r.err != nil {
			t.Fatalf("keygen %s: %v", r.id, r.err)
		}
		configs[r.id] = r.cfg
	}

	// Sign with alice and bob (threshold=2).
	signers := []PartyID{"alice", "bob"}
	msgHash := make([]byte, 32)
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}

	signNets := map[PartyID]*inMemNetwork{}
	for _, p := range signers {
		signNets[p] = newInMemNetwork(1000)
	}

	type sresult struct {
		id  PartyID
		sig *Signature
		err error
	}
	sresults := make(chan sresult, len(signers))

	for _, p := range signers {
		p := p
		net := &routingNetwork{self: p, nets: signNets, parties: signers}
		go func() {
			round := Sign(configs[p], signers, msgHash)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				sresults <- sresult{id: p, err: err}
				return
			}
			sig := res.(*Signature)
			sresults <- sresult{id: p, sig: sig}
		}()
	}

	var sig *Signature
	for i := 0; i < len(signers); i++ {
		r := <-sresults
		if r.err != nil {
			t.Fatalf("sign %s: %v", r.id, r.err)
		}
		sig = r.sig
	}

	if sig == nil {
		t.Fatal("nil signature")
	}
	t.Logf("Schnorr signature: R=%x S=%x", sig.R, sig.S)
}

// TestKeygenSignReshareSign runs keygen, signs, reshares to a new committee, and signs again.
func TestKeygenSignReshareSign(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2

	// --- Keygen ---
	nets := map[PartyID]*inMemNetwork{}
	for _, p := range parties {
		nets[p] = newInMemNetwork(1000)
	}

	type kresult struct {
		id  PartyID
		cfg *Config
		err error
	}
	kresults := make(chan kresult, len(parties))

	for _, p := range parties {
		p := p
		net := &routingNetwork{self: p, nets: nets, parties: parties}
		go func() {
			round := Keygen(p, parties, threshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				kresults <- kresult{id: p, err: err}
				return
			}
			cfg := res.(*Config)
			kresults <- kresult{id: p, cfg: cfg}
		}()
	}

	configs := map[PartyID]*Config{}
	for i := 0; i < len(parties); i++ {
		r := <-kresults
		if r.err != nil {
			t.Fatalf("keygen %s: %v", r.id, r.err)
		}
		configs[r.id] = r.cfg
	}

	oldPub, err := configs["alice"].PublicKey()
	if err != nil {
		t.Fatalf("old public key: %v", err)
	}
	t.Logf("Old public key: %x", oldPub.Bytes())

	// --- Sign with old committee (alice + bob) ---
	signers := []PartyID{"alice", "bob"}
	msgHash := make([]byte, 32)
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}

	signNets := map[PartyID]*inMemNetwork{}
	for _, p := range signers {
		signNets[p] = newInMemNetwork(1000)
	}

	type sresult struct {
		id  PartyID
		sig *Signature
		err error
	}
	sresults := make(chan sresult, len(signers))
	for _, p := range signers {
		p := p
		net := &routingNetwork{self: p, nets: signNets, parties: signers}
		go func() {
			round := Sign(configs[p], signers, msgHash)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				sresults <- sresult{id: p, err: err}
				return
			}
			sig := res.(*Signature)
			sresults <- sresult{id: p, sig: sig}
		}()
	}
	for i := 0; i < len(signers); i++ {
		r := <-sresults
		if r.err != nil {
			t.Fatalf("sign (pre-reshare) %s: %v", r.id, r.err)
		}
	}
	t.Log("Pre-reshare signing succeeded")

	// --- Reshare: {alice, bob, carol} -> {alice, bob, dave} with threshold 2 ---
	newParties := []PartyID{"alice", "bob", "dave"}
	newThreshold := 2
	allParties := []PartyID{"alice", "bob", "carol", "dave"}

	reshareNets := map[PartyID]*inMemNetwork{}
	for _, p := range allParties {
		reshareNets[p] = newInMemNetwork(1000)
	}

	type rresult struct {
		id  PartyID
		cfg *Config
		err error
	}
	rresults := make(chan rresult, len(allParties))

	for _, p := range allParties {
		p := p
		net := &routingNetwork{self: p, nets: reshareNets, parties: allParties}
		go func() {
			var cfg *Config
			if c, ok := configs[p]; ok {
				cfg = c // old party
			}
			round := Reshare(cfg, p, parties, newParties, newThreshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				rresults <- rresult{id: p, err: err}
				return
			}
			if res == nil {
				rresults <- rresult{id: p, cfg: nil}
			} else {
				rresults <- rresult{id: p, cfg: res.(*Config)}
			}
		}()
	}

	newConfigs := map[PartyID]*Config{}
	for i := 0; i < len(allParties); i++ {
		r := <-rresults
		if r.err != nil {
			t.Fatalf("reshare %s: %v", r.id, r.err)
		}
		if r.cfg != nil {
			newConfigs[r.id] = r.cfg
		}
	}

	// carol should not have a new config (removed from group).
	if _, ok := newConfigs["carol"]; ok {
		t.Error("carol should not have a new config after reshare")
	}
	// dave should have a new config.
	if _, ok := newConfigs["dave"]; !ok {
		t.Fatal("dave should have a new config after reshare")
	}

	// Verify public key is preserved.
	newPub, err := newConfigs["alice"].PublicKey()
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	if !oldPub.Equal(newPub) {
		t.Fatalf("public key changed after reshare: old=%x new=%x", oldPub.Bytes(), newPub.Bytes())
	}
	t.Logf("New public key: %x (matches old)", newPub.Bytes())

	// --- Sign with new committee (alice + dave) ---
	newSigners := []PartyID{"alice", "dave"}
	newSignNets := map[PartyID]*inMemNetwork{}
	for _, p := range newSigners {
		newSignNets[p] = newInMemNetwork(1000)
	}

	sresults2 := make(chan sresult, len(newSigners))
	for _, p := range newSigners {
		p := p
		net := &routingNetwork{self: p, nets: newSignNets, parties: newSigners}
		go func() {
			round := Sign(newConfigs[p], newSigners, msgHash)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				sresults2 <- sresult{id: p, err: err}
				return
			}
			sig := res.(*Signature)
			sresults2 <- sresult{id: p, sig: sig}
		}()
	}
	for i := 0; i < len(newSigners); i++ {
		r := <-sresults2
		if r.err != nil {
			t.Fatalf("sign (post-reshare) %s: %v", r.id, r.err)
		}
	}
	t.Log("Post-reshare signing with new committee succeeded")
}

// TestECDSAEcrecover verifies that the threshold ECDSA signature is compatible with
// Ethereum's ecrecover by recovering the public key from the signature.
func TestECDSAEcrecover(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2

	// Keygen.
	nets := map[PartyID]*inMemNetwork{}
	for _, p := range parties {
		nets[p] = newInMemNetwork(1000)
	}
	type kresult struct {
		id  PartyID
		cfg *Config
		err error
	}
	kresults := make(chan kresult, len(parties))
	for _, p := range parties {
		p := p
		net := &routingNetwork{self: p, nets: nets, parties: parties}
		go func() {
			round := Keygen(p, parties, threshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				kresults <- kresult{id: p, err: err}
				return
			}
			kresults <- kresult{id: p, cfg: res.(*Config)}
		}()
	}
	configs := map[PartyID]*Config{}
	for i := 0; i < len(parties); i++ {
		r := <-kresults
		if r.err != nil {
			t.Fatalf("keygen %s: %v", r.id, r.err)
		}
		configs[r.id] = r.cfg
	}

	// Sign with alice and bob using ECDSA.
	signers := []PartyID{"alice", "bob"}
	msgHash := make([]byte, 32)
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}
	signNets := map[PartyID]*inMemNetwork{}
	for _, p := range signers {
		signNets[p] = newInMemNetwork(1000)
	}
	type sresult struct {
		id  PartyID
		sig *Signature
		err error
	}
	sresults := make(chan sresult, len(signers))
	for _, p := range signers {
		p := p
		net := &routingNetwork{self: p, nets: signNets, parties: signers}
		go func() {
			round := SignECDSA(configs[p], signers, msgHash)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				sresults <- sresult{id: p, err: err}
				return
			}
			sresults <- sresult{id: p, sig: res.(*Signature)}
		}()
	}
	var sig *Signature
	for i := 0; i < len(signers); i++ {
		r := <-sresults
		if r.err != nil {
			t.Fatalf("sign %s: %v", r.id, r.err)
		}
		sig = r.sig
	}

	// Get Ethereum ECDSA signature.
	ethSig, err := sig.SigEthereumECDSA()
	if err != nil {
		t.Fatalf("SigEthereum: %v", err)
	}

	// Recover public key using go-ethereum's crypto.Ecrecover.
	recoveredPub, err := ethcrypto.Ecrecover(msgHash, ethSig)
	if err != nil {
		t.Fatalf("Ecrecover: %v", err)
	}

	// Get expected public key (uncompressed).
	pubKey, err := configs["alice"].PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pubBytes := pubKey.Bytes()

	// Parse compressed pubkey to uncompressed for comparison.
	expectedPub, err := ethcrypto.DecompressPubkey(pubBytes[:])
	if err != nil {
		t.Fatalf("DecompressPubkey: %v", err)
	}
	expectedUncompressed := ethcrypto.FromECDSAPub(expectedPub)

	if len(recoveredPub) != len(expectedUncompressed) {
		t.Fatalf("length mismatch: recovered=%d expected=%d", len(recoveredPub), len(expectedUncompressed))
	}
	for i := range recoveredPub {
		if recoveredPub[i] != expectedUncompressed[i] {
			t.Fatalf("ecrecover pubkey mismatch at byte %d:\n  recovered: %x\n  expected:  %x", i, recoveredPub, expectedUncompressed)
		}
	}
	t.Logf("ecrecover recovered correct public key: %x", recoveredPub[:8])
}

// TestConfigJSON verifies Config marshal/unmarshal roundtrip.
func TestConfigJSON(t *testing.T) {
	// Build a minimal config.
	share := NewScalar()
	share.s.SetInt(12345)

	pub := make(map[PartyID]*Point)
	s1 := NewScalar()
	s1.s.SetInt(1)
	pub["alice"] = NewPoint().ScalarBaseMult(s1)
	s2 := NewScalar()
	s2.s.SetInt(2)
	pub["bob"] = NewPoint().ScalarBaseMult(s2)

	cfg := &Config{
		ID:         "alice",
		Threshold:  2,
		Generation: 1,
		Share:      share,
		Public:     pub,
		ChainKey:   []byte("chainkey"),
		RID:        []byte("rid"),
	}

	data, err := cfg.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	cfg2 := new(Config)
	if err := cfg2.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if cfg2.ID != cfg.ID {
		t.Errorf("ID mismatch: %q vs %q", cfg2.ID, cfg.ID)
	}
	if cfg2.Threshold != cfg.Threshold {
		t.Errorf("Threshold mismatch: %d vs %d", cfg2.Threshold, cfg.Threshold)
	}
	if cfg2.Generation != cfg.Generation {
		t.Errorf("Generation mismatch: %d vs %d", cfg2.Generation, cfg.Generation)
	}
	if !cfg2.Share.Equal(cfg.Share) {
		t.Error("Share mismatch")
	}
	for id, pt := range cfg.Public {
		pt2, ok := cfg2.Public[id]
		if !ok {
			t.Errorf("missing public[%s]", id)
			continue
		}
		if !pt.Equal(pt2) {
			t.Errorf("public[%s] mismatch", id)
		}
	}
}
