package node

import (
	"context"
	"errors"

	"signet/tss"
)

// RemoteKeyManager implements KeyManager by forwarding requests to an
// external KMS process over gRPC. This is a Phase 1/2 stub — all methods
// return errNotImplemented until the Rust KMS is available.
type RemoteKeyManager struct {
	socket string
}

var errNotImplemented = errors.New("remote key manager not implemented; requires KMS process")

// NewRemoteKeyManager creates a RemoteKeyManager that will connect to the
// KMS at the given Unix socket path.
func NewRemoteKeyManager(socket string) *RemoteKeyManager {
	return &RemoteKeyManager{socket: socket}
}

func (rkm *RemoteKeyManager) RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error) {
	return nil, errNotImplemented
}

func (rkm *RemoteKeyManager) RunSign(ctx context.Context, p SignParams) (*tss.Signature, error) {
	return nil, errNotImplemented
}

func (rkm *RemoteKeyManager) GetKeyInfo(groupID, keyID string) (*KeyInfo, error) {
	return nil, errNotImplemented
}

func (rkm *RemoteKeyManager) ListKeys(groupID string) ([]string, error) {
	return nil, errNotImplemented
}

func (rkm *RemoteKeyManager) ListGroups() ([]string, error) {
	return nil, errNotImplemented
}

func (rkm *RemoteKeyManager) Close() error {
	return nil
}

// Ensure RemoteKeyManager implements KeyManager at compile time.
var _ KeyManager = (*RemoteKeyManager)(nil)
