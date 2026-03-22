package tss

import (
	"context"
	"encoding/json"
	"testing"
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

func TestScalarArithmetic(t *testing.T) {
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

	d := a.Mul(b)
	var exp35 [32]byte
	exp35[31] = 35
	if d.Bytes() != exp35 {
		t.Errorf("Mul: expected 35, got %x", d.Bytes())
	}

	aInv := a.Inverse()
	one := a.Mul(aInv)
	var expOne [32]byte
	expOne[31] = 1
	if one.Bytes() != expOne {
		t.Errorf("Inverse: a * a^-1 != 1")
	}

	aNeg := a.Negate()
	zero := a.Add(aNeg)
	if !zero.IsZero() {
		t.Errorf("Negate: a + (-a) != 0")
	}
}

func TestPointArithmetic(t *testing.T) {
	G := GeneratorPoint()
	if G.IsIdentity() {
		t.Fatal("generator should not be identity")
	}

	two := NewScalar()
	two.s.SetInt(2)
	twoG := NewPoint().ScalarBaseMult(two)
	GplusG := G.Add(G)
	if !twoG.Equal(GplusG) {
		t.Error("2*G != G+G")
	}

	b := G.Bytes()
	G2, err := PointFromBytes(b)
	if err != nil {
		t.Fatalf("PointFromBytes: %v", err)
	}
	if !G.Equal(G2) {
		t.Error("serialization round-trip failed")
	}
}

func TestLagrange(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
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

func TestPolynomial(t *testing.T) {
	secret := NewScalar()
	secret.s.SetInt(42)

	poly, err := NewPolynomial(2, secret)
	if err != nil {
		t.Fatalf("NewPolynomial: %v", err)
	}

	zero := NewScalar()
	zero.s.SetInt(0)
	result := poly.Evaluate(zero)
	if !result.Equal(secret) {
		t.Errorf("f(0) != secret: got %x want %x", result.Bytes(), secret.Bytes())
	}
}

func TestKeygenRoundtrip(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2

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
		net := &routingNetwork{self: p, nets: nets, parties: parties}
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

	// All parties should get the same group public key.
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
	t.Logf("FROST group public key: %x", pub0.Bytes())
}

func TestKeygenAndSign(t *testing.T) {
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
	if sig == nil {
		t.Fatal("nil signature")
	}
	t.Logf("FROST signature: R=%x Z=%x", sig.R, sig.Z)

	// Verify SigEthereum encoding.
	ethSig, err := sig.SigEthereum()
	if err != nil {
		t.Fatalf("SigEthereum: %v", err)
	}
	if len(ethSig) != 65 {
		t.Errorf("expected 65-byte eth sig, got %d", len(ethSig))
	}
}

func TestConfigJSON(t *testing.T) {
	share := NewScalar()
	share.s.SetInt(12345)

	// Use a real group key (generator point).
	G := GeneratorPoint()
	groupKeyBytes := G.Bytes()

	cfg := &Config{
		ID:         "alice",
		Threshold:  2,
		Generation: 1,
		Share:      share,
		GroupKey:   groupKeyBytes[:],
		Parties:    []PartyID{"alice", "bob"},
		ChainKey:   []byte("chainkey"),
		RID:        []byte("rid"),
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	cfg2 := new(Config)
	if err := json.Unmarshal(data, cfg2); err != nil {
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
	if len(cfg2.GroupKey) != 33 {
		t.Errorf("GroupKey length: got %d, want 33", len(cfg2.GroupKey))
	}
	for i, b := range cfg.GroupKey {
		if cfg2.GroupKey[i] != b {
			t.Errorf("GroupKey[%d] mismatch: got %x, want %x", i, cfg2.GroupKey[i], b)
		}
	}
}
