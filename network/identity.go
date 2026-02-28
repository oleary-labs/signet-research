package network

import (
	"fmt"
	"os"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/luxfi/threshold/pkg/party"
)

// LoadOrGenerateKey loads a private key from path, or generates and saves a new Ed25519 key.
// File format: raw protobuf bytes from crypto.MarshalPrivateKey. Perms: 0600.
func LoadOrGenerateKey(path string) (crypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}

	// Generate new Ed25519 key.
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	data, err = crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("write key file %s: %w", path, err)
	}

	return priv, nil
}

// PartyIDFromPrivKey derives party.ID = party.ID(peer.IDFromPrivateKey(priv).String()).
func PartyIDFromPrivKey(priv crypto.PrivKey) (party.ID, error) {
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("peer ID from key: %w", err)
	}
	return party.ID(pid.String()), nil
}
