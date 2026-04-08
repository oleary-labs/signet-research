package node

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"

	"signet/tss"
)

// LocalKeyManager implements KeyManager by running the FROST protocol
// in-process via the tss package. It owns the KeyShardStore (bbolt) and an
// in-memory config cache.
type LocalKeyManager struct {
	store *KeyShardStore
	log   *zap.Logger

	mu      sync.RWMutex
	configs map[shardKey]*tss.Config
}

// NewLocalKeyManager creates a LocalKeyManager backed by a bbolt store in dataDir.
func NewLocalKeyManager(ctx context.Context, dataDir string, log *zap.Logger) (*LocalKeyManager, error) {
	store, err := openKeyShardStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &LocalKeyManager{
		store:   store,
		log:     log,
		configs: make(map[shardKey]*tss.Config),
	}, nil
}

// RunKeygen executes the FROST keygen protocol, persists the result, and
// returns the public key info. Persist failure is logged as a warning but
// is not fatal — the config is still cached in memory.
func (lkm *LocalKeyManager) RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error) {
	round := tss.Keygen(p.Host.Self(), p.Parties, p.Threshold)

	result, err := tss.Run(ctx, round, p.SN)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	cfg, ok := result.(*tss.Config)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}

	if err := lkm.store.Put(p.GroupID, p.KeyID, cfg); err != nil {
		lkm.log.Warn("persist shard failed",
			zap.String("group_id", p.GroupID),
			zap.String("key_id", p.KeyID),
			zap.Error(err))
	}

	k := shardKey{p.GroupID, p.KeyID}
	lkm.mu.Lock()
	lkm.configs[k] = cfg
	lkm.mu.Unlock()

	return configToKeyInfo(cfg), nil
}

// RunSign executes the FROST signing protocol using the stored key config.
func (lkm *LocalKeyManager) RunSign(ctx context.Context, p SignParams) (*tss.Signature, error) {
	cfg, err := lkm.loadConfig(p.GroupID, p.KeyID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("key not found: group=%s key=%s", p.GroupID, p.KeyID)
	}

	round := tss.Sign(cfg, p.Signers, p.MessageHash)

	result, err := tss.Run(ctx, round, p.SN)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	sig, ok := result.(*tss.Signature)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}
	return sig, nil
}

// GetKeyInfo returns public metadata for a stored key, or (nil, nil) if not found.
func (lkm *LocalKeyManager) GetKeyInfo(groupID, keyID string) (*KeyInfo, error) {
	cfg, err := lkm.loadConfig(groupID, keyID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return configToKeyInfo(cfg), nil
}

// ListKeys returns all key IDs stored under groupID.
func (lkm *LocalKeyManager) ListKeys(groupID string) ([]string, error) {
	return lkm.store.List(groupID)
}

// ListGroups returns all group IDs that have at least one stored key.
func (lkm *LocalKeyManager) ListGroups() ([]string, error) {
	return lkm.store.ListGroups()
}

// Close closes the underlying key shard store.
func (lkm *LocalKeyManager) Close() error {
	return lkm.store.Close()
}

// loadConfig returns a config from the in-memory cache, or loads it from the
// store and caches it. Returns (nil, nil) when not found.
func (lkm *LocalKeyManager) loadConfig(groupID, keyID string) (*tss.Config, error) {
	k := shardKey{groupID, keyID}

	lkm.mu.RLock()
	cfg, ok := lkm.configs[k]
	lkm.mu.RUnlock()
	if ok {
		return cfg, nil
	}

	cfg, err := lkm.store.Get(groupID, keyID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	lkm.mu.Lock()
	lkm.configs[k] = cfg
	lkm.mu.Unlock()
	return cfg, nil
}

// configToKeyInfo extracts public metadata from a tss.Config.
func configToKeyInfo(cfg *tss.Config) *KeyInfo {
	return &KeyInfo{
		GroupKey:  cfg.GroupKey,
		PartyID:  cfg.ID,
		Parties:  cfg.Parties,
		Threshold: cfg.Threshold,
	}
}

// Ensure LocalKeyManager implements KeyManager at compile time.
var _ KeyManager = (*LocalKeyManager)(nil)
