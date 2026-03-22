package tss

import (
	"crypto/rand"
	"fmt"
)

// Polynomial is a degree-(threshold-1) polynomial over secp256k1 scalars.
// f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
type Polynomial struct {
	coeffs []*Scalar // coeffs[0] is the constant term (secret)
}

// NewPolynomial creates a random polynomial of degree threshold-1 with the
// given secret as the constant term.
func NewPolynomial(threshold int, secret *Scalar) (*Polynomial, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("threshold must be >= 1")
	}
	coeffs := make([]*Scalar, threshold)
	coeffs[0] = secret
	for i := 1; i < threshold; i++ {
		sc, err := randomScalar()
		if err != nil {
			return nil, fmt.Errorf("random scalar: %w", err)
		}
		coeffs[i] = sc
	}
	return &Polynomial{coeffs: coeffs}, nil
}

// Evaluate computes f(x) using Horner's method.
func (p *Polynomial) Evaluate(x *Scalar) *Scalar {
	result := NewScalar()
	result.s.Set(&p.coeffs[len(p.coeffs)-1].s)
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		result = result.Mul(x)
		result = result.Add(p.coeffs[i])
	}
	return result
}

// Coefficients returns the polynomial coefficients (constant term first).
func (p *Polynomial) Coefficients() []*Scalar {
	return p.coeffs
}

// randomScalar generates a cryptographically random non-zero scalar mod N.
func randomScalar() (*Scalar, error) {
	for {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		sc := ScalarFromBytes(b)
		if !sc.IsZero() {
			return sc, nil
		}
	}
}
