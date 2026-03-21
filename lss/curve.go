package lss

import (
	"fmt"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Scalar wraps secp256k1.ModNScalar for arithmetic mod the curve order N.
type Scalar struct {
	s secp256k1.ModNScalar
}

// NewScalar returns a zero scalar.
func NewScalar() *Scalar { return &Scalar{} }

// ScalarFromBytes sets the scalar from a big-endian 32-byte array, reducing mod N.
func ScalarFromBytes(b [32]byte) *Scalar {
	sc := &Scalar{}
	sc.s.SetByteSlice(b[:])
	return sc
}

// ScalarFromBigInt sets the scalar from a big.Int, reducing mod N.
func ScalarFromBigInt(n *big.Int) *Scalar {
	b := n.Bytes()
	// pad to 32 bytes
	var buf [32]byte
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(buf[32-len(b):], b)
	return ScalarFromBytes(buf)
}

// Add returns a new scalar equal to s + t mod N.
func (s *Scalar) Add(t *Scalar) *Scalar {
	result := &Scalar{}
	result.s.Set(&s.s)
	result.s.Add(&t.s)
	return result
}

// Mul returns a new scalar equal to s * t mod N.
func (s *Scalar) Mul(t *Scalar) *Scalar {
	result := &Scalar{}
	result.s.Set(&s.s)
	result.s.Mul(&t.s)
	return result
}

// Negate returns a new scalar equal to -s mod N.
func (s *Scalar) Negate() *Scalar {
	result := &Scalar{}
	result.s.Set(&s.s)
	result.s.Negate()
	return result
}

// Inverse returns a new scalar equal to 1/s mod N.
func (s *Scalar) Inverse() *Scalar {
	result := &Scalar{}
	result.s.Set(&s.s)
	result.s.InverseNonConst()
	return result
}

// IsZero returns true if the scalar is zero.
func (s *Scalar) IsZero() bool { return s.s.IsZero() }

// IsOverHalfOrder returns true if the scalar is greater than n/2 (secp256k1 curve order / 2).
// Used for EIP-2 low-s normalization.
func (s *Scalar) IsOverHalfOrder() bool {
	neg := s.Negate()
	sBytes := s.Bytes()
	negBytes := neg.Bytes()
	for i := 0; i < 32; i++ {
		if sBytes[i] < negBytes[i] {
			return false
		}
		if sBytes[i] > negBytes[i] {
			return true
		}
	}
	return false // equal means s == n/2, treated as not over
}

// Bytes returns the big-endian 32-byte encoding.
func (s *Scalar) Bytes() [32]byte { return s.s.Bytes() }

// Equal returns true if s == t.
func (s *Scalar) Equal(t *Scalar) bool { return s.s.Equals(&t.s) }

// Point wraps a secp256k1 Jacobian point.
type Point struct {
	p secp256k1.JacobianPoint
}

// NewPoint returns the point at infinity (identity element).
func NewPoint() *Point { return &Point{} }

// GeneratorPoint returns the secp256k1 generator G.
func GeneratorPoint() *Point {
	pt := &Point{}
	var one secp256k1.ModNScalar
	one.SetInt(1)
	secp256k1.ScalarBaseMultNonConst(&one, &pt.p)
	return pt
}

// Add returns p + q.
func (p *Point) Add(q *Point) *Point {
	result := &Point{}
	secp256k1.AddNonConst(&p.p, &q.p, &result.p)
	return result
}

// ScalarMult returns s * p.
func (p *Point) ScalarMult(s *Scalar) *Point {
	result := &Point{}
	sc := s.s // copy
	secp256k1.ScalarMultNonConst(&sc, &p.p, &result.p)
	return result
}

// ScalarBaseMult returns s * G.
func (p *Point) ScalarBaseMult(s *Scalar) *Point {
	result := &Point{}
	sc := s.s // copy
	secp256k1.ScalarBaseMultNonConst(&sc, &result.p)
	return result
}

// IsIdentity returns true if the point is the identity (infinity).
func (p *Point) IsIdentity() bool {
	pt := p.p
	pt.ToAffine()
	return pt.X.IsZero() && pt.Y.IsZero()
}

// Equal returns true if p == q.
func (p *Point) Equal(q *Point) bool {
	pp := p.p
	pp.ToAffine()
	qp := q.p
	qp.ToAffine()
	return pp.X.Equals(&qp.X) && pp.Y.Equals(&qp.Y)
}

// XScalar returns the x-coordinate of p as a scalar mod N.
func (p *Point) XScalar() *Scalar {
	pt := p.p
	pt.ToAffine()
	// Convert FieldVal to scalar: extract bytes then load as scalar
	xBytes := pt.X.Bytes()
	result := &Scalar{}
	result.s.SetByteSlice(xBytes[:])
	return result
}

// Bytes returns the 33-byte compressed encoding of p.
func (p *Point) Bytes() [33]byte {
	pt := p.p
	pt.ToAffine()
	pub := secp256k1.NewPublicKey(&pt.X, &pt.Y)
	compressed := pub.SerializeCompressed()
	var out [33]byte
	copy(out[:], compressed)
	return out
}

// MarshalBinary returns the 33-byte compressed encoding (implements binary marshaler).
func (p *Point) MarshalBinary() ([]byte, error) {
	b := p.Bytes()
	return b[:], nil
}

// PointFromBytes parses a 33-byte compressed secp256k1 point.
func PointFromBytes(b [33]byte) (*Point, error) {
	pub, err := secp256k1.ParsePubKey(b[:])
	if err != nil {
		return nil, fmt.Errorf("parse point: %w", err)
	}
	pt := &Point{}
	pub.AsJacobian(&pt.p)
	return pt, nil
}

// PointFromSlice parses a compressed secp256k1 point from a byte slice.
func PointFromSlice(b []byte) (*Point, error) {
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse point: %w", err)
	}
	pt := &Point{}
	pub.AsJacobian(&pt.p)
	return pt, nil
}

