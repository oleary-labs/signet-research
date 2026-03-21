package main

import (
	"context"
	"fmt"
	"signet/lss"

	"github.com/ethereum/go-ethereum/crypto"
)

type inMemNet struct{ ch chan *lss.Message }

func newNet(buf int) *inMemNet { return &inMemNet{ch: make(chan *lss.Message, buf)} }

func (n *inMemNet) Send(msg *lss.Message)        { n.ch <- msg }
func (n *inMemNet) Incoming() <-chan *lss.Message { return n.ch }

type routeNet struct {
	self    lss.PartyID
	nets    map[lss.PartyID]*inMemNet
	parties []lss.PartyID
}

func (r *routeNet) Incoming() <-chan *lss.Message { return r.nets[r.self].ch }
func (r *routeNet) Send(msg *lss.Message) {
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

func main() {
	parties := []lss.PartyID{"alice", "bob", "carol"}
	threshold := 2

	nets := map[lss.PartyID]*inMemNet{}
	for _, p := range parties {
		nets[p] = newNet(1000)
	}

	type kres struct {
		id  lss.PartyID
		cfg *lss.Config
		err error
	}
	kch := make(chan kres, 3)
	for _, p := range parties {
		p := p
		go func() {
			net := &routeNet{self: p, nets: nets, parties: parties}
			round := lss.Keygen(p, parties, threshold)
			res, err := lss.Run(context.Background(), round, net)
			if err != nil {
				kch <- kres{id: p, err: err}
				return
			}
			kch <- kres{id: p, cfg: res.(*lss.Config)}
		}()
	}
	configs := map[lss.PartyID]*lss.Config{}
	for i := 0; i < 3; i++ {
		r := <-kch
		if r.err != nil {
			panic(r.err)
		}
		configs[r.id] = r.cfg
	}

	signers := []lss.PartyID{"alice", "bob"}
	msgHash := make([]byte, 32)
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}

	signNets := map[lss.PartyID]*inMemNet{}
	for _, p := range signers {
		signNets[p] = newNet(1000)
	}

	type sres struct {
		id  lss.PartyID
		sig *lss.Signature
		err error
	}
	sch := make(chan sres, 2)
	for _, p := range signers {
		p := p
		go func() {
			net := &routeNet{self: p, nets: signNets, parties: signers}
			round := lss.Sign(configs[p], signers, msgHash)
			res, err := lss.Run(context.Background(), round, net)
			if err != nil {
				sch <- sres{id: p, err: err}
				return
			}
			sch <- sres{id: p, sig: res.(*lss.Signature)}
		}()
	}
	var sig *lss.Signature
	for i := 0; i < 2; i++ {
		r := <-sch
		if r.err != nil {
			panic(r.err)
		}
		sig = r.sig
	}

	ethSig, err := sig.SigEthereum()
	if err != nil {
		panic(err)
	}

	pubKey, err := configs["alice"].PublicKey()
	if err != nil {
		panic(err)
	}
	pubBytes := pubKey.Bytes()
	ecdsaPub, err := crypto.DecompressPubkey(pubBytes[:])
	if err != nil {
		panic(err)
	}
	addr := crypto.PubkeyToAddress(*ecdsaPub)

	fmt.Printf("    bytes32 constant MSG_HASH = 0x%x;\n", msgHash)
	fmt.Printf("    address constant SIGNER = %s;\n", addr)
	fmt.Printf("    bytes32 constant SIG_RX = 0x%x;\n", ethSig[:32])
	fmt.Printf("    bytes32 constant SIG_S = 0x%x;\n", ethSig[32:64])
	fmt.Printf("    uint8 constant SIG_V = %d;\n", ethSig[64])
}
