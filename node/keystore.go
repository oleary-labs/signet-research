package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/protocols/lss"
)

// saveConfig persists a *lss.Config to disk using JSON serialization.
// The file is written with mode 0600 (secret key material).
func saveConfig(path string, cfg *lss.Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// loadConfig reads a *lss.Config from disk. Returns os.ErrNotExist (unwrapped via
// errors.Is) when the file does not exist.
func loadConfig(path string) (*lss.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("read: %w", err)
	}
	cfg := lss.EmptyConfig(curve.Secp256k1{})
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return cfg, nil
}
