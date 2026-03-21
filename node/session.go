package node

import (
	"context"
	"fmt"

	"signet/lss"
	"signet/network"
)

// runKeygenOn executes the LSS keygen protocol using an already-created SessionNetwork.
// The caller is responsible for closing sn when done.
func runKeygenOn(
	ctx context.Context,
	host *network.Host,
	sn *network.SessionNetwork,
	sessionID string,
	parties []lss.PartyID,
	threshold int,
) (*lss.Config, error) {
	round := lss.Keygen(host.Self(), parties, threshold)

	result, err := lss.Run(ctx, round, sn)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	cfg, ok := result.(*lss.Config)
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
	cfg *lss.Config,
	signers []lss.PartyID,
	messageHash []byte,
) (*lss.Signature, error) {
	round := lss.Sign(cfg, signers, messageHash)

	result, err := lss.Run(ctx, round, sn)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	sig, ok := result.(*lss.Signature)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}
	return sig, nil
}
