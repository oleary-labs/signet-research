package tss

import "fmt"

// Signature is the output of a threshold FROST signing session.
type Signature struct {
	R [33]byte // compressed nonce point R
	Z [32]byte // aggregate signature scalar z
}

// SigEthereum returns a 65-byte signature encoding: R.x(32) || z(32) || v(1).
// v is the recovery bit (R.y parity: 0=even, 1=odd).
// This format is used by the on-chain FROSTVerifier via the ecrecover trick.
func (sig *Signature) SigEthereum() ([]byte, error) {
	Rpt, err := PointFromBytes(sig.R)
	if err != nil {
		return nil, fmt.Errorf("parse R: %w", err)
	}
	rBytes := Rpt.XScalar().Bytes()

	// Recovery bit: 0 if R.Y is even, 1 if odd.
	v := byte(0)
	if sig.R[0] == 0x03 {
		v = 1
	}

	out := make([]byte, 65)
	copy(out[:32], rBytes[:])
	copy(out[32:64], sig.Z[:])
	out[64] = v
	return out, nil
}
