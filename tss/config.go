package tss

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Config is the per-party persistent state after keygen or reshare.
type Config struct {
	ID         PartyID   `json:"-"`
	Threshold  int       `json:"-"`
	Generation uint64    `json:"-"`
	Share      *Scalar   // our secret share x_i
	GroupKey   []byte    // 33-byte compressed group public key Y
	Parties    []PartyID // sorted list of all parties in this key share set
	ChainKey   []byte
	RID        []byte
}

// PublicKey returns the group public key by parsing GroupKey.
func (c *Config) PublicKey() (*Point, error) {
	if len(c.GroupKey) != 33 {
		return nil, fmt.Errorf("invalid group key length %d", len(c.GroupKey))
	}
	return PointFromSlice(c.GroupKey)
}

// PublicPoint is an alias for PublicKey.
func (c *Config) PublicPoint() (*Point, error) {
	return c.PublicKey()
}

// PartyIDs returns the sorted party IDs for this key share set.
func (c *Config) PartyIDs() PartyIDSlice {
	return NewPartyIDSlice(c.Parties)
}

// Validate checks that the config is well-formed.
func (c *Config) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("empty party ID")
	}
	if c.Threshold < 1 {
		return fmt.Errorf("threshold must be >= 1")
	}
	if c.Share == nil {
		return fmt.Errorf("nil share")
	}
	if len(c.GroupKey) != 33 {
		return fmt.Errorf("invalid group key: expected 33 bytes, got %d", len(c.GroupKey))
	}
	if len(c.Parties) < c.Threshold {
		return fmt.Errorf("insufficient parties: have %d, need %d", len(c.Parties), c.Threshold)
	}
	found := false
	for _, p := range c.Parties {
		if p == c.ID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("self (%s) not in parties list", c.ID)
	}
	return nil
}

// configJSON is the wire format for JSON marshaling.
type configJSON struct {
	ID         string   `json:"id"`
	Threshold  int      `json:"threshold"`
	Generation uint64   `json:"generation"`
	Share      string   `json:"share"`     // hex, 32 bytes
	GroupKey   string   `json:"group_key"` // hex, 33 bytes
	Parties    []string `json:"parties"`
	ChainKey   string   `json:"chain_key"` // hex
	RID        string   `json:"rid"`       // hex
}

// MarshalJSON encodes the Config with hex-encoded scalars and points.
func (c *Config) MarshalJSON() ([]byte, error) {
	parties := make([]string, len(c.Parties))
	for i, p := range c.Parties {
		parties[i] = string(p)
	}
	var shareHex string
	if c.Share != nil {
		b := c.Share.Bytes()
		shareHex = hex.EncodeToString(b[:])
	}
	return json.Marshal(&configJSON{
		ID:         string(c.ID),
		Threshold:  c.Threshold,
		Generation: c.Generation,
		Share:      shareHex,
		GroupKey:   hex.EncodeToString(c.GroupKey),
		Parties:    parties,
		ChainKey:   hex.EncodeToString(c.ChainKey),
		RID:        hex.EncodeToString(c.RID),
	})
}

// UnmarshalJSON decodes a Config from hex-encoded JSON.
func (c *Config) UnmarshalJSON(data []byte) error {
	var raw configJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.ID = PartyID(raw.ID)
	c.Threshold = raw.Threshold
	c.Generation = raw.Generation

	shareBytes, err := hex.DecodeString(raw.Share)
	if err != nil {
		return fmt.Errorf("decode share: %w", err)
	}
	var shareArr [32]byte
	copy(shareArr[:], shareBytes)
	c.Share = ScalarFromBytes(shareArr)

	groupKey, err := hex.DecodeString(raw.GroupKey)
	if err != nil {
		return fmt.Errorf("decode group_key: %w", err)
	}
	c.GroupKey = groupKey

	c.Parties = make([]PartyID, len(raw.Parties))
	for i, p := range raw.Parties {
		c.Parties[i] = PartyID(p)
	}

	chainKey, err := hex.DecodeString(raw.ChainKey)
	if err != nil {
		return fmt.Errorf("decode chain_key: %w", err)
	}
	c.ChainKey = chainKey

	rid, err := hex.DecodeString(raw.RID)
	if err != nil {
		return fmt.Errorf("decode rid: %w", err)
	}
	c.RID = rid

	return nil
}
