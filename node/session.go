package node

import (
	"context"
	"fmt"

	"signet/tss"
	"signet/network"
)

// runKeygenOn executes the LSS keygen protocol using an already-created SessionNetwork.
// The caller is responsible for closing sn when done.
func runKeygenOn(
	ctx context.Context,
	host *network.Host,
	sn *network.SessionNetwork,
	sessionID string,
	parties []tss.PartyID,
	threshold int,
) (*tss.Config, error) {
	round := tss.Keygen(host.Self(), parties, threshold)

	result, err := tss.Run(ctx, round, sn)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	cfg, ok := result.(*tss.Config)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}
	return cfg, nil
}

// runSignOn executes the LSS sign protocol using an already-created SessionNetwork.
// The caller is responsible for closing sn when done.
func runSignOn(
	ctx context.Context,
	host *network.Host,
	sn *network.SessionNetwork,
	signSessionID string,
	cfg *tss.Config,
	signers []tss.PartyID,
	messageHash []byte,
) (*tss.Signature, error) {
	round := tss.Sign(cfg, signers, messageHash)

	result, err := tss.Run(ctx, round, sn)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	sig, ok := result.(*tss.Signature)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}
	return sig, nil
}
