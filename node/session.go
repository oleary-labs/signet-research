package node

import (
	"context"
	"fmt"

	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"

	"signet/network"
)

// runKeygenOn executes the CMP keygen protocol using an already-created SessionNetwork.
// The caller is responsible for closing sn when done.
func runKeygenOn(
	ctx context.Context,
	host *network.Host,
	sn *network.SessionNetwork,
	sessionID string,
	parties []party.ID,
	threshold int,
	pl *pool.Pool,
) (*cmp.Config, error) {
	startFunc := cmp.Keygen(curve.Secp256k1{}, host.Self(), parties, threshold, pl)
	handler, err := protocol.NewMultiHandler(startFunc, []byte(sessionID))
	if err != nil {
		return nil, fmt.Errorf("new handler: %w", err)
	}

	go network.HandlerLoop(handler, sn)

	result, err := handler.WaitForResult()
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	cfg, ok := result.(*cmp.Config)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}
	return cfg, nil
}

// runSignOn executes the CMP sign protocol using an already-created SessionNetwork.
// The caller is responsible for closing sn when done.
func runSignOn(
	ctx context.Context,
	host *network.Host,
	sn *network.SessionNetwork,
	signSessionID string,
	cfg *cmp.Config,
	signers []party.ID,
	messageHash []byte,
	pl *pool.Pool,
) (*ecdsa.Signature, error) {
	startFunc := cmp.Sign(cfg, signers, messageHash, pl)
	handler, err := protocol.NewMultiHandler(startFunc, []byte(signSessionID))
	if err != nil {
		return nil, fmt.Errorf("new handler: %w", err)
	}

	go network.HandlerLoop(handler, sn)

	result, err := handler.WaitForResult()
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	sig, ok := result.(*ecdsa.Signature)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}
	return sig, nil
}
