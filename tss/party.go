package tss

import (
	"crypto/sha256"
	"fmt"
	"sort"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// PartyID is a string identifier for a party in a threshold protocol.
type PartyID string

// Scalar derives a deterministic non-zero scalar from the party ID using SHA-256.
func (id PartyID) Scalar() *Scalar {
	h := sha256.Sum256([]byte(id))
	sc := ScalarFromBytes(h)
	// If the hash happens to be zero mod N (astronomically unlikely), increment.
	if sc.IsZero() {
		var one secp256k1.ModNScalar
		one.SetInt(1)
		sc.s.Add(&one)
	}
	return sc
}

// PartyIDSlice is a sorted, deduplicated slice of party IDs.
type PartyIDSlice []PartyID

// NewPartyIDSlice creates a sorted and deduplicated PartyIDSlice from the given IDs.
func NewPartyIDSlice(ids []PartyID) PartyIDSlice {
	cp := make([]PartyID, len(ids))
	copy(cp, ids)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	// dedup
	out := cp[:0]
	for i, id := range cp {
		if i == 0 || id != cp[i-1] {
			out = append(out, id)
		}
	}
	return PartyIDSlice(out)
}

// Contains returns true if id is in the slice.
func (s PartyIDSlice) Contains(id PartyID) bool {
	for _, p := range s {
		if p == id {
			return true
		}
	}
	return false
}

// LagrangeCoefficient computes the Lagrange coefficient for `self` evaluated at x=0
// given the set of signers. Each party's "x coordinate" is derived from its PartyID
// scalar: x_i = PartyID.Scalar().
//
// λ_self(0) = ∏_{j ≠ self} x_j / (x_j - x_self)   (mod N)
func LagrangeCoefficient(signers []PartyID, self PartyID) (*Scalar, error) {
	xSelf := self.Scalar()

	num := NewScalar()
	num.s.SetInt(1)
	den := NewScalar()
	den.s.SetInt(1)

	for _, j := range signers {
		if j == self {
			continue
		}
		xj := j.Scalar()
		num = num.Mul(xj)
		diff := xj.Add(xSelf.Negate()) // x_j - x_self
		if diff.IsZero() {
			return nil, fmt.Errorf("lagrange: duplicate x-coordinate for %s and %s", j, self)
		}
		den = den.Mul(diff)
	}

	return num.Mul(den.Inverse()), nil
}
