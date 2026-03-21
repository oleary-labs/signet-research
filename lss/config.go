package lss

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Config is the per-party persistent state after keygen or reshare.
type Config struct {
	ID         PartyID            `json:"-"` // marshaled separately
	Threshold  int                `json:"-"`
	Generation uint64             `json:"-"`
	Share      *Scalar            // our secret share
	Public     map[PartyID]*Point // public share for each party: share_i * G
	ChainKey   []byte
	RID        []byte
}

// PublicKey computes the group public key via Lagrange interpolation of public shares.
// It uses the first `Threshold` parties from the Public map.
func (c *Config) PublicKey() (*Point, error) {
	parties := c.PartyIDs()
	if len(parties) < c.Threshold {
		return nil, fmt.Errorf("not enough parties: have %d, need %d", len(parties), c.Threshold)
	}
	// Use any threshold-sized subset; we use the first t parties.
	subset := []PartyID(parties[:c.Threshold])

	result := NewPoint()
	for _, id := range subset {
		pub, ok := c.Public[id]
		if !ok {
			return nil, fmt.Errorf("missing public share for party %s", id)
		}
		lambda, err := LagrangeCoefficient(subset, id)
		if err != nil {
			return nil, fmt.Errorf("lagrange for %s: %w", id, err)
		}
		term := pub.ScalarMult(lambda)
		result = result.Add(term)
	}
	return result, nil
}

// PublicPoint is an alias for PublicKey that returns (curve.Point, error)
// matching the interface used in node/node.go (cfg.PublicPoint()).
func (c *Config) PublicPoint() (*Point, error) {
	return c.PublicKey()
}

// PartyIDs returns a sorted slice of all party IDs in the Public map.
func (c *Config) PartyIDs() PartyIDSlice {
	ids := make([]PartyID, 0, len(c.Public))
	for id := range c.Public {
		ids = append(ids, id)
	}
	return NewPartyIDSlice(ids)
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
	if len(c.Public) < c.Threshold {
		return fmt.Errorf("insufficient public shares")
	}
	if _, ok := c.Public[c.ID]; !ok {
		return fmt.Errorf("missing self public share")
	}
	return nil
}

// configJSON is the wire format for Config.
type configJSON struct {
	ID         string            `json:"id"`
	Threshold  int               `json:"threshold"`
	Generation uint64            `json:"generation"`
	Share      string            `json:"share"`   // hex
	Public     map[string]string `json:"public"`  // partyID -> hex compressed point
	ChainKey   string            `json:"chain_key"` // hex
	RID        string            `json:"rid"`     // hex
}

// MarshalJSON encodes the Config with hex-encoded scalars and points.
func (c *Config) MarshalJSON() ([]byte, error) {
	pub := make(map[string]string, len(c.Public))
	for id, pt := range c.Public {
		b := pt.Bytes()
		pub[string(id)] = hex.EncodeToString(b[:])
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
		Public:     pub,
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

	c.Public = make(map[PartyID]*Point, len(raw.Public))
	for idStr, ptHex := range raw.Public {
		ptBytes, err := hex.DecodeString(ptHex)
		if err != nil {
			return fmt.Errorf("decode public[%s]: %w", idStr, err)
		}
		pt, err := PointFromSlice(ptBytes)
		if err != nil {
			return fmt.Errorf("parse public[%s]: %w", idStr, err)
		}
		c.Public[PartyID(idStr)] = pt
	}

	chainKeyBytes, err := hex.DecodeString(raw.ChainKey)
	if err != nil {
		return fmt.Errorf("decode chain_key: %w", err)
	}
	c.ChainKey = chainKeyBytes

	ridBytes, err := hex.DecodeString(raw.RID)
	if err != nil {
		return fmt.Errorf("decode rid: %w", err)
	}
	c.RID = ridBytes

	return nil
}
