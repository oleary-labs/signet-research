package node

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"go.etcd.io/bbolt"

	"signet/tss"
)

var (
	bucketPending  = []byte("pending")
	bucketVersions = []byte("versions")
)

// KeyVersionStore manages pending reshare results and historical key versions
// in a separate bbolt database (keyshards_archive.db). This keeps the active
// key store (keyshards.db) clean and makes garbage collection trivial: when no
// reshares are in flight, the entire archive db can be safely deleted.
type KeyVersionStore struct {
	db *bbolt.DB
}

// openKeyVersionStore opens (or creates) keyshards_archive.db under dataDir.
func openKeyVersionStore(dataDir string) (*KeyVersionStore, error) {
	db, err := bbolt.Open(filepath.Join(dataDir, "keyshards_archive.db"), 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("open archive db: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketPending); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketVersions)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("create archive buckets: %w", err)
	}
	return &KeyVersionStore{db: db}, nil
}

// WritePending stores an in-flight reshare result. This does NOT touch the
// active key store. The pending entry is promoted to active by CommitPending
// on the KeyShardStore, or discarded on retry/failure.
func (s *KeyVersionStore) WritePending(groupID, keyID string, cfg *tss.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal pending: %w", err)
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		grp, err := tx.Bucket(bucketPending).CreateBucketIfNotExists([]byte(groupID))
		if err != nil {
			return err
		}
		return grp.Put([]byte(keyID), data)
	})
}

// GetPending returns the pending reshare result, or (nil, nil) if none exists.
func (s *KeyVersionStore) GetPending(groupID, keyID string) (*tss.Config, error) {
	var data []byte
	if err := s.db.View(func(tx *bbolt.Tx) error {
		grp := tx.Bucket(bucketPending).Bucket([]byte(groupID))
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
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	cfg := new(tss.Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal pending: %w", err)
	}
	return cfg, nil
}

// DiscardPending deletes a pending reshare result. Called on retry or failure.
func (s *KeyVersionStore) DiscardPending(groupID, keyID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		grp := tx.Bucket(bucketPending).Bucket([]byte(groupID))
		if grp == nil {
			return nil
		}
		return grp.Delete([]byte(keyID))
	})
}

// ArchiveVersion saves a committed key config as a historical version.
// The version key is "<keyID>:v<generation>".
func (s *KeyVersionStore) ArchiveVersion(groupID, keyID string, cfg *tss.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal version: %w", err)
	}
	vKey := fmt.Sprintf("%s:v%d", keyID, cfg.Generation)
	return s.db.Update(func(tx *bbolt.Tx) error {
		grp, err := tx.Bucket(bucketVersions).CreateBucketIfNotExists([]byte(groupID))
		if err != nil {
			return err
		}
		return grp.Put([]byte(vKey), data)
	})
}

// GetVersion returns a specific historical version, or (nil, nil) if not found.
func (s *KeyVersionStore) GetVersion(groupID, keyID string, generation uint64) (*tss.Config, error) {
	vKey := fmt.Sprintf("%s:v%d", keyID, generation)
	var data []byte
	if err := s.db.View(func(tx *bbolt.Tx) error {
		grp := tx.Bucket(bucketVersions).Bucket([]byte(groupID))
		if grp == nil {
			return nil
		}
		v := grp.Get([]byte(vKey))
		if v != nil {
			data = make([]byte, len(v))
			copy(data, v)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	cfg := new(tss.Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal version: %w", err)
	}
	return cfg, nil
}

// Close closes the archive database.
func (s *KeyVersionStore) Close() error {
	return s.db.Close()
}
