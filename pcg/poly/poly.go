package poly

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
)

// Polynomial represents a polynomial where the index is the power of x and the value is the coefficient.
type Polynomial struct {
	Coefficients []*bls12381.Fr
}

func (a *Polynomial) Equal(b Polynomial) bool {
	if len(a.Coefficients) != len(b.Coefficients) {
		return false
	}
	for i, aValue := range a.Coefficients {
		if !aValue.Equal(b.Coefficients[i]) {
			return false
		}
	}
	return true
}

// NewPoly converts slice of *bls12381.Fr to Polynomial representation.
func NewPoly(values []*bls12381.Fr) Polynomial {
	return Polynomial{Coefficients: values}
}

// Add adds two polynomials.
func (a *Polynomial) Add(b Polynomial) Polynomial {
	maxLen := max(len(a.Coefficients), len(b.Coefficients))
	rValues := make([]*bls12381.Fr, maxLen)

	for i := 0; i < maxLen; i++ {
		coefficientA := bls12381.NewFr()
		if i < len(a.Coefficients) {
			coefficientA.Set(a.Coefficients[i])
		}
		coefficientB := bls12381.NewFr()
		if i < len(b.Coefficients) {
			coefficientB.Set(b.Coefficients[i])
		}
		rValues[i] = bls12381.NewFr()
		rValues[i].Add(coefficientA, coefficientB)
	}
	a.Coefficients = rValues
	return NewPoly(rValues)
}

// Sub subtracts two polynomials.
func (a *Polynomial) Sub(b Polynomial) Polynomial {
	maxLen := max(len(a.Coefficients), len(b.Coefficients))
	rValues := make([]*bls12381.Fr, maxLen)

	for i := 0; i < maxLen; i++ {
		coefficientA := bls12381.NewFr()
		if i < len(a.Coefficients) {
			coefficientA.Set(a.Coefficients[i])
		}
		coefficientB := bls12381.NewFr()
		if i < len(b.Coefficients) {
			coefficientB.Set(b.Coefficients[i])
		}
		rValues[i] = bls12381.NewFr()
		rValues[i].Sub(coefficientA, coefficientB)
	}
	a.Coefficients = rValues
	return NewPoly(rValues)
}

// MulNaive multiplies two polynomials in O(n^2) time.
func (a *Polynomial) MulNaive(b Polynomial) (Polynomial, error) {
	if len(a.Coefficients) != len(b.Coefficients) {
		return Polynomial{}, fmt.Errorf("polynomials must have the same length")
	}

	rValues := make([]*bls12381.Fr, len(a.Coefficients)+len(b.Coefficients)-1)
	for i := range rValues {
		rValues[i] = bls12381.NewFr()
	}
	for i, aValue := range a.Coefficients {
		for j, bValue := range b.Coefficients {
			k := i + j
			m := bls12381.NewFr()
			m.Mul(aValue, bValue)
			rValues[k].Add(rValues[k], m)
		}
	}
	a.Coefficients = rValues
	return NewPoly(rValues), nil
}

// MulByConstant multiplies a polynomial by a constant.
func (a *Polynomial) MulByConstant(c *bls12381.Fr) Polynomial {
	rValues := make([]*bls12381.Fr, len(a.Coefficients))
	for i, aValue := range a.Coefficients {
		rValues[i] = bls12381.NewFr()
		rValues[i].Mul(aValue, c)
	}
	a.Coefficients = rValues
	return NewPoly(rValues)
}
