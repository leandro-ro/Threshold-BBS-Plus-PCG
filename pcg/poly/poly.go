package poly

import (
	bls12381 "github.com/kilic/bls12-381"
)

// Polynomial represents a polynomial where the index is the power of x and the value is the coefficient.
type Polynomial struct {
	Coefficients []*bls12381.Fr
}

// PolyFromFrSlice is a placeholder for converting slice to Polynomial.
func PolyFromFrSlice(values []*bls12381.Fr) Polynomial {
	return Polynomial{Coefficients: values}
}

// AddPolys adds two polynomials.
func AddPolys(a, b Polynomial) Polynomial {
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

	return PolyFromFrSlice(rValues)
}

// SubPolys subtracts two polynomials.
func SubPolys(a, b Polynomial) Polynomial {
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

	return PolyFromFrSlice(rValues)
}

// MulPolysNaive multiplies two polynomials in O(n^2) time.
func MulPolysNaive(a, b Polynomial) Polynomial {
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
	return PolyFromFrSlice(rValues)
}

// NTT performs the Number Theoretic Transform on a polynomial with bls12381.Fr coefficients.
func NTT(a []*bls12381.Fr, root *bls12381.Fr) []*bls12381.Fr {
	if len(a) == 1 {
		return a
	}

	length := len(a)

	// Split the polynomial into even and odd terms
	even := make([]*bls12381.Fr, length/2)
	odd := make([]*bls12381.Fr, length/2)
	for i := range even {
		even[i] = a[2*i]
		odd[i] = a[2*i+1]
	}

	// Recursively apply NTT
	yEven := NTT(even, root)
	yOdd := NTT(odd, root)

	// Combine the results
	y := make([]*bls12381.Fr, length)
	omega := bls12381.NewFr().One() // Initialize omega to 1 (or the appropriate unity element in your field)
	for k := 0; k < length/2; k++ {
		omegaK := bls12381.NewFr()
		omegaK.Mul(omega, root)

		omegaMyOdd := bls12381.NewFr()
		omegaMyOdd.Mul(omega, yOdd[k])

		y[k] = bls12381.NewFr()
		y[k].Add(yEven[k], omegaMyOdd)

		y[k+length/2] = bls12381.NewFr().Sub(yEven[k], bls12381.NewFr().Mul(omegaK, yOdd[k]))
		omega.Mul(omega, root)
	}

	return y
}

// MulPolysNTT multiplies two polynomials using NTT.
func MulPolysNTT(a, b Polynomial, root *bls12381.Fr) Polynomial {

	// Apply NTT to both polynomials
	nttA := NTT(a.Coefficients, root)
	nttB := NTT(b.Coefficients, root)

	// Point-wise multiply the transformed polynomials
	resultCoeffs := make([]*bls12381.Fr, length)
	for i := range nttA {
		resultCoeffs[i] = bls12381.NewFr().Mul(nttA[i], nttB[i])
	}

	// Apply inverse NTT to the result
	// Ensure you have an inverse NTT function and the appropriate inverse root
	result := InverseNTT(resultCoeffs, inverseRoot, length)

	// Convert back to polynomial
	return PolyFromFrSlice(result)
}

// MulPolyByConstant multiplies a polynomial by a constant.
func MulPolyByConstant(a Polynomial, c *bls12381.Fr) Polynomial {
	rValues := make([]*bls12381.Fr, len(a.Coefficients))
	for i, aValue := range a.Coefficients {
		rValues[i] = bls12381.NewFr()
		rValues[i].Mul(aValue, c)
	}
	return PolyFromFrSlice(rValues)
}

// Helper function to find the maximum of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
