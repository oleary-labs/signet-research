package node

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/protocols/lss"
	bolt "go.etcd.io/bbolt"
)

var shardsBucket = []byte("keyshards")

// KeyShardStore persists lss.Config values keyed by session ID in a bbolt database.
type KeyShardStore struct {
	db *bolt.DB
}

// openKeyShardStore opens (or creates) the keyshards.db file under dataDir.
// dataDir must already exist.
func openKeyShardStore(dataDir string) (*KeyShardStore, error) {
	db, err := bolt.Open(filepath.Join(dataDir, "keyshards.db"), 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("open bbolt: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(shardsBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("create bucket: %w", err)
	}
	return &KeyShardStore{db: db}, nil
}

// Put stores cfg under sessionID, overwriting any existing entry.
func (s *KeyShardStore) Put(sessionID string, cfg *lss.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(shardsBucket).Put([]byte(sessionID), data)
	})
}

// Get returns the config for sessionID, or (nil, nil) if not found.
func (s *KeyShardStore) Get(sessionID string) (*lss.Config, error) {
	var data []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(shardsBucket).Get([]byte(sessionID))
		if v != nil {
			data = make([]byte, len(v))
			copy(data, v)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("bbolt view: %w", err)
	}
	if data == nil {
		return nil, nil
	}
	cfg := lss.EmptyConfig(curve.Secp256k1{})
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return cfg, nil
}

// List returns all session IDs stored in the database.
func (s *KeyShardStore) List() ([]string, error) {
	var ids []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(shardsBucket).ForEach(func(k, _ []byte) error {
			ids = append(ids, string(k))
			return nil
		})
	})
	return ids, err
}

// Close closes the underlying database.
func (s *KeyShardStore) Close() error {
	return s.db.Close()
}
