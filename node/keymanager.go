package node

import (
	"context"

	"signet/network"
	"signet/tss"
)

// KeyManager is the interface between the node and whatever process holds key
// material. Today that is LocalKeyManager (in-process tss); after the KMS
// migration it will be RemoteKeyManager (gRPC to Rust KMS).
type KeyManager interface {
	// RunKeygen executes the key generation protocol, persists the result,
	// and returns public metadata about the new key.
	RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error)

	// RunSign executes the threshold signing protocol using a previously
	// generated key identified by (GroupID, KeyID) in the params.
	RunSign(ctx context.Context, p SignParams) (*tss.Signature, error)

	// GetKeyInfo returns public metadata for a stored key shard, or
	// (nil, nil) if the key does not exist.
	GetKeyInfo(groupID, keyID string) (*KeyInfo, error)

	// ListKeys returns all key IDs stored under groupID.
	ListKeys(groupID string) ([]string, error)

	// ListGroups returns all group IDs that have at least one stored key.
	ListGroups() ([]string, error)

	// Close releases resources (e.g. the key shard database).
	Close() error
}

// KeygenParams holds the inputs for a keygen session.
type KeygenParams struct {
	Host      *network.Host
	SN        *network.SessionNetwork
	SessionID string
	GroupID   string
	KeyID     string
	Parties   []tss.PartyID
	Threshold int
}

// SignParams holds the inputs for a signing session.
type SignParams struct {
	Host        *network.Host
	SN          *network.SessionNetwork
	SessionID   string
	GroupID     string
	KeyID       string
	Signers     []tss.PartyID
	MessageHash []byte
}

// KeyInfo holds public metadata about a stored key shard. It does not contain
// secret key material.
type KeyInfo struct {
	GroupKey  []byte        // 33-byte compressed secp256k1 group public key
	PartyID  tss.PartyID   // this node's party ID
	Parties  []tss.PartyID // all parties in the key group
	Threshold int
}
