package node

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"go.etcd.io/bbolt"

	"signet/tss"
)

var shardsBucket = []byte("keyshards")

// KeyShardStore persists tss.Config values in a bbolt database, keyed by
// (groupID, keyID). The on-disk layout uses nested buckets:
//
//	"keyshards"            — root bucket
//	  └─ "<groupID>"       — one sub-bucket per group
//	       └─ "<keyID>"    — JSON-encoded tss.Config
type KeyShardStore struct {
	db *bbolt.DB
}

// openKeyShardStore opens (or creates) the keyshards.db file under dataDir.
// dataDir must already exist.
func openKeyShardStore(dataDir string) (*KeyShardStore, error) {
	db, err := bbolt.Open(filepath.Join(dataDir, "keyshards.db"), 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("open bbolt: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(shardsBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("create root bucket: %w", err)
	}
	return &KeyShardStore{db: db}, nil
}

// Put stores cfg under (groupID, keyID), overwriting any existing entry.
func (s *KeyShardStore) Put(groupID, keyID string, cfg *tss.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket(shardsBucket)
		grp, err := root.CreateBucketIfNotExists([]byte(groupID))
		if err != nil {
			return fmt.Errorf("create group bucket: %w", err)
		}
		return grp.Put([]byte(keyID), data)
	})
}

// Get returns the config for (groupID, keyID), or (nil, nil) if not found.
func (s *KeyShardStore) Get(groupID, keyID string) (*tss.Config, error) {
	var data []byte
	if err := s.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket(shardsBucket)
		grp := root.Bucket([]byte(groupID))
		if grp == nil {
			return nil
		}
		v := grp.Get([]byte(keyID))
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
	cfg := new(tss.Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return cfg, nil
}

// List returns all key IDs stored under groupID.
func (s *KeyShardStore) List(groupID string) ([]string, error) {
	var ids []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket(shardsBucket)
		grp := root.Bucket([]byte(groupID))
		if grp == nil {
			return nil
		}
		return grp.ForEach(func(k, _ []byte) error {
			ids = append(ids, string(k))
			return nil
		})
	})
	return ids, err
}

// ListGroups returns all group IDs that have at least one key stored.
func (s *KeyShardStore) ListGroups() ([]string, error) {
	var groups []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(shardsBucket).ForEach(func(k, v []byte) error {
			if v == nil {
				// v == nil means k is a sub-bucket name, not a value
				groups = append(groups, string(k))
			}
			return nil
		})
	})
	return groups, err
}

// Close closes the underlying database.
func (s *KeyShardStore) Close() error {
	return s.db.Close()
}
