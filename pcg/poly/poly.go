package poly

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math"
	"math/big"
	"sort"
)

// Polynomial represents a polynomial where the index is the power of x and the value is the coefficient.
// Sparse polynomials are represented by setting the isSparse flag to true and setting the nonZeroPos slice.
// This allows for faster multiplication of high degree polynomials.
type Polynomial struct {
	Coefficients []*bls12381.Fr // Coefficients holds the coefficients of the polynomial.
	IsSparse     bool           // isSparse indicates if the polynomial is sparse which indicates that most zero coefficients are zero.
	nonZeroPos   []int          // Sparse holds the indices/exponent of the non-zero coefficients in Coefficients.
}

// NewFromFr converts slice of *bls12381.Fr to Polynomial representation.
// The index of the slice is the power of x and the value is the coefficient.
func NewFromFr(values []*bls12381.Fr) Polynomial {
	return Polynomial{Coefficients: values, IsSparse: false, nonZeroPos: nil}
}

// NewFromBig converts slice of *big.Int to Polynomial representation.
// The index of the slice is the power of x and the value is the coefficient.
func NewFromBig(values []*big.Int) Polynomial {
	rValues := make([]*bls12381.Fr, len(values))
	for i, value := range values {
		rValues[i] = bls12381.NewFr()
		rValues[i].FromBytes(value.Bytes())
	}
	return NewFromFr(rValues)
}

// NewSparse converts slice of *bls12381.Fr to Polynomial representation.
// coefficients and exponents must have the same length.
func NewSparse(coefficients []*bls12381.Fr, exponents []*big.Int) (Polynomial, error) {
	if len(coefficients) != len(exponents) {
		return Polynomial{}, fmt.Errorf("length of coefficients and exponents must match")
	}
	if hasDuplicatesBigInt(exponents) {
		return Polynomial{}, fmt.Errorf("duplicate exponents. each exponent must be unique")
	}

	// Find the maximum exponent to determine the size of the Coefficients slice
	maxExponent := big.NewInt(0)
	for _, exponent := range exponents {
		if exponent.Cmp(maxExponent) > 0 {
			maxExponent.Set(exponent)
		}
	}

	// Initialize the Coefficients slice with zeros
	polyCoefficients := make([]*bls12381.Fr, maxExponent.Int64()+1)
	for i := range polyCoefficients {
		polyCoefficients[i] = bls12381.NewFr()
		polyCoefficients[i].Zero()
	}

	// Set the non-zero coefficients
	nonZeroPos := make([]int, 0, len(coefficients))
	for i, coeff := range coefficients {
		if !coeff.IsZero() {
			index := int(exponents[i].Int64())
			polyCoefficients[index].Set(coeff)
			nonZeroPos = append(nonZeroPos, index)
		}
	}

	sort.Ints(nonZeroPos)
	return Polynomial{
		Coefficients: polyCoefficients,
		IsSparse:     true,
		nonZeroPos:   nonZeroPos,
	}, nil
}

// Equal checks if two polynomials are equal.
func (a *Polynomial) Equal(b Polynomial) bool {
	if len(a.Coefficients) != len(b.Coefficients) {
		return false
	}
	for i := range a.Coefficients {
		if !a.getCoefficient(i).Equal(b.getCoefficient(i)) {
			return false
		}
	}
	return true
}

// Add adds two polynomials and stores the result in the first polynomial.
func (a *Polynomial) Add(b Polynomial) Polynomial {
	maxLen := max(len(a.Coefficients), len(b.Coefficients))
	rValues := make([]*bls12381.Fr, maxLen)

	for i := 0; i < maxLen; i++ {
		coefficientA := bls12381.NewFr()
		if i < len(a.Coefficients) {
			coefficientA.Set(a.getCoefficient(i))
		} else {
			coefficientA.Zero()
		}
		coefficientB := bls12381.NewFr()
		if i < len(b.Coefficients) {
			coefficientB.Set(b.getCoefficient(i))
		} else {
			coefficientB.Zero()
		}
		rValues[i] = bls12381.NewFr()
		rValues[i].Add(coefficientA, coefficientB)
	}
	a.Coefficients = rValues
	return NewFromFr(rValues)
}

// Sub subtracts two polynomials and stores the result in the first polynomial.
func (a *Polynomial) Sub(b Polynomial) Polynomial {
	maxLen := max(len(a.Coefficients), len(b.Coefficients))
	rValues := make([]*bls12381.Fr, maxLen)

	for i := 0; i < maxLen; i++ {
		coefficientA := bls12381.NewFr()
		if i < len(a.Coefficients) {
			coefficientA.Set(a.getCoefficient(i))
		}
		coefficientB := bls12381.NewFr()
		if i < len(b.Coefficients) {
			coefficientB.Set(b.getCoefficient(i))
		}
		rValues[i] = bls12381.NewFr()
		rValues[i].Sub(coefficientA, coefficientB)
	}
	a.Coefficients = rValues
	return NewFromFr(rValues)
}

// Mul multiplies polynomial a with polynomial b and returns the result.
// The original polynomials are not modified.
// If both polynomials are sparse, it uses more efficient sparse multiplication.
// If the length of the polynomials is less than 256, it uses naive multiplication.
// Otherwise, it uses FFT.
func (a *Polynomial) Mul(b Polynomial) (Polynomial, error) {
	// Ensure both polynomials have the same length
	aLen := len(a.Coefficients)
	bLen := len(b.Coefficients)
	maxLen := max(aLen, bLen)

	// Create temporary slices to store the adjusted coefficients if needed
	aCopy := a.Copy()
	bCopy := b.Copy()
	if aLen != bLen {
		if aLen != maxLen {
			aCopy.Coefficients = make([]*bls12381.Fr, maxLen)
			copy(aCopy.Coefficients, a.Coefficients)
			for i := aLen; i < maxLen; i++ {
				aCopy.Coefficients[i] = bls12381.NewFr()
				aCopy.Coefficients[i].Zero()
			}
		}
		if bLen != maxLen {
			bCopy.Coefficients = make([]*bls12381.Fr, maxLen)
			copy(bCopy.Coefficients, b.Coefficients)
			for i := bLen; i < maxLen; i++ {
				bCopy.Coefficients[i] = bls12381.NewFr()
				bCopy.Coefficients[i].Zero()
			}
		}
	}

	if aCopy.IsSparse && bCopy.IsSparse {
		return aCopy.mulSparse(bCopy)
	}

	if len(aCopy.Coefficients) < 256 {
		return aCopy.mulNaive(bCopy)
	}
	return aCopy.mulFast(bCopy)
}

// mulNaive multiplies two polynomials in O(n^2).
func (a *Polynomial) mulNaive(b Polynomial) (Polynomial, error) {
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

	return NewFromFr(rValues), nil
}

// mulSparse efficiently multiplies two sparse polynomials.
func (a *Polynomial) mulSparse(b Polynomial) (Polynomial, error) {
	if len(a.Coefficients) != len(b.Coefficients) {
		return Polynomial{}, fmt.Errorf("polynomials must have the same length")
	} else if !(a.IsSparse && b.IsSparse) {
		return Polynomial{}, fmt.Errorf("both polynomials must be sparse")
	}

	// Determine the maximum index for the result polynomial
	maxIndex := 0
	for _, pos := range a.nonZeroPos {
		for _, bPos := range b.nonZeroPos {
			if pos+bPos > maxIndex {
				maxIndex = pos + bPos
			}
		}
	}

	// Initialize the result polynomial
	rValues := make([]*bls12381.Fr, maxIndex+1)
	for i := range rValues {
		rValues[i] = bls12381.NewFr()
		rValues[i].Zero()
	}

	// Multiply non-zero coefficients and add the result to the correct position
	nonZeroPosResult := make([]int, 0)
	for _, aPos := range a.nonZeroPos {
		for _, bPos := range b.nonZeroPos {
			resultPos := aPos + bPos
			m := bls12381.NewFr()
			m.Mul(a.Coefficients[aPos], b.Coefficients[bPos])
			rValues[resultPos].Add(rValues[resultPos], m)

			if !m.IsZero() {
				nonZeroPosResult = append(nonZeroPosResult, resultPos)
			}
		}
	}

	// Remove duplicate indices from nonZeroPosResult
	uniqueNonZeroPosResult := unique(nonZeroPosResult)

	isSparse := true
	if len(uniqueNonZeroPosResult) > 1024 {
		isSparse = false
		uniqueNonZeroPosResult = nil
	}

	return Polynomial{
		Coefficients: rValues,
		IsSparse:     isSparse,
		nonZeroPos:   uniqueNonZeroPosResult,
	}, nil
}

// mulFast multiplies two polynomials in O(nlogn) using FFT.
func (a *Polynomial) mulFast(b Polynomial) (Polynomial, error) {
	if len(a.Coefficients) != len(b.Coefficients) {
		return Polynomial{}, fmt.Errorf("polynomials must have the same length")
	}

	n := math.Ceil(math.Log2(float64(len(a.Coefficients))))
	fft, err := NewBLS12381FFT(int(n))
	if err != nil {
		return Polynomial{}, err
	}
	resultBig, err := fft.MulPolysFFT(a.ToBig(), b.ToBig())
	if err != nil {
		return Polynomial{}, err
	}
	result := NewFromBig(resultBig)

	return result, nil
}

// MulByConstant multiplies the polynomial by a constant.
// It changes the original polynomial and returns a copy of it.
func (a *Polynomial) MulByConstant(c *bls12381.Fr) Polynomial {
	if a.IsSparse { // Knowing the polynomial is sparse we can only multiply the non-zero coefficients
		for _, pos := range a.nonZeroPos {
			a.Coefficients[pos].Mul(a.Coefficients[pos], c)
		}
	} else {
		for i := range a.Coefficients {
			a.Coefficients[i].Mul(a.Coefficients[i], c)
		}
	}
	return a.Copy()
}

// ToBig converts a polynomial to a slice of *big.Int.
func (a *Polynomial) ToBig() []*big.Int {
	rValues := make([]*big.Int, len(a.Coefficients))
	for i, aValue := range a.Coefficients {
		rValues[i] = aValue.ToBig()
	}
	return rValues
}

// Copy returns a copy of the polynomial.
func (a *Polynomial) Copy() Polynomial {
	rValues := make([]*bls12381.Fr, len(a.Coefficients))
	if a.IsSparse {
		for _, pos := range a.nonZeroPos {
			rValues[pos] = bls12381.NewFr().Set(a.Coefficients[pos])
		}
	} else {
		for i, aValue := range a.Coefficients {
			rValues[i] = bls12381.NewFr().Set(aValue)
		}
	}

	poly := NewFromFr(rValues)
	poly.IsSparse = a.IsSparse
	if a.IsSparse {
		poly.nonZeroPos = make([]int, len(a.nonZeroPos))
		copy(poly.nonZeroPos, a.nonZeroPos)
	}
	return poly
}

// SparseBigAdd adds a slice of *big.Int to the coefficients of a sparse polynomial.
// It changes the original polynomial and returns nil if successful.
func (a *Polynomial) SparseBigAdd(b []*big.Int) error {
	if !a.IsSparse {
		return fmt.Errorf("polynomial must be sparse to use SparseBigAdd")
	} else if len(a.nonZeroPos) != len(b) {
		return fmt.Errorf("length of the big.int slice must match with the number of non-zero coefficients")
	}

	for i, pos := range a.nonZeroPos {
		element := bls12381.NewFr()
		element.FromBytes(b[i].Bytes())
		a.Coefficients[pos].Add(a.Coefficients[pos], element)
	}

	return nil
}

func (a *Polynomial) getCoefficient(i int) *bls12381.Fr {
	if a.Coefficients[i] == nil {
		return bls12381.NewFr().Zero()
	}
	return a.Coefficients[i]
}

// unique removes duplicate integers from a slice.
func unique(intSlice []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// hasDuplicatesBigInt checks if there are duplicates in a slice of *big.Int.
func hasDuplicatesBigInt(slice []*big.Int) bool {
	seen := make(map[string]struct{})

	for _, num := range slice {
		numStr := num.String() // Convert *big.Int to string for map key
		if _, exists := seen[numStr]; exists {
			return true // Duplicate found
		}
		seen[numStr] = struct{}{}
	}

	return false
}
