package poly

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math"
	"math/big"
	"math/rand"
)

// Polynomial represents a polynomial in the form of a map: exponent -> coefficient.
type Polynomial struct {
	coefficients map[int]*bls12381.Fr // coefficients of the polynomial in the form of a map: exponent -> coefficient
}

// NewFromFr converts slice of *bls12381.Fr to Polynomial representation.
// The index of the element will be its exponent.
func NewFromFr(values []*bls12381.Fr) *Polynomial {
	coefficients := make(map[int]*bls12381.Fr)
	for i, v := range values {
		// Ensure that only non-zero coefficients are stored for efficiency.
		if !v.IsZero() {
			coefficients[i] = v
		}
	}

	return &Polynomial{
		coefficients: coefficients,
	}
}

// NewFromBig converts slice of *big.Int to Polynomial representation.
// The index of the element will be its exponent.
func NewFromBig(values []*big.Int) *Polynomial {
	rValues := make([]*bls12381.Fr, len(values))
	for i, value := range values {
		// Do not check for zero values here, as NewFromFr will do.
		rValues[i] = bls12381.NewFr()
		rValues[i].FromBytes(value.Bytes())
	}
	return NewFromFr(rValues)
}

// NewSparse creates a new sparse polynomial with the given coefficients and their exponents.
// The index of the coefficient will determine the respective exponent in the exponents slice.
// Note that coefficients can be zero, but the respective exponents is accordingly ignored.
// The exponents must be unique.
func NewSparse(coefficients []*bls12381.Fr, exponents []*big.Int) (*Polynomial, error) {
	if len(coefficients) != len(exponents) {
		return nil, fmt.Errorf("length of coefficients and exponents must be equal")
	}
	if hasDuplicates(exponents) {
		return nil, fmt.Errorf("exponents must not be unique")
	}

	p := &Polynomial{
		coefficients: make(map[int]*bls12381.Fr),
	}

	for i, c := range coefficients {
		// Ensure that only non-zero coefficients are stored for efficiency.
		if !c.IsZero() {
			val := bls12381.NewFr().Set(c)
			p.coefficients[int(exponents[i].Int64())] = val
		}
	}

	return p, nil
}

// NewRandomPolynomial creates a random polynomial of the given degree.
// Every coefficient is a random element in Fr, hence the polynomial is not sparse.
func NewRandomPolynomial(rng *rand.Rand, degree int) (*Polynomial, error) {
	coefficients := make([]*bls12381.Fr, degree)
	for i := 0; i < degree; i++ {
		randElement, err := bls12381.NewFr().Rand(rng)
		if err != nil {
			return nil, err
		}
		coefficients[i] = bls12381.NewFr()
		coefficients[i].Set(randElement)
	}
	return NewFromFr(coefficients), nil
}

// Degree returns the degree of the polynomial.
// If the polynomial is empty, it returns an error.
func (p *Polynomial) Degree() (int, error) {
	deg, found := maxKey(p.coefficients)
	if !found {
		return -1, fmt.Errorf("polynomial is empty")
	}
	return deg, nil
}

// Equal checks if two polynomials are equal.
func (p *Polynomial) Equal(q *Polynomial) bool {
	if len(p.coefficients) != len(q.coefficients) { // Quick check
		return false
	}

	for exp, coeff := range p.coefficients {
		if val, ok := q.coefficients[exp]; !ok || !val.Equal(coeff) {
			return false
		}
	}

	return true
}

// Copy returns a copy of the polynomial the function is being called on.
func (p *Polynomial) Copy() *Polynomial {
	newPoly := &Polynomial{
		coefficients: make(map[int]*bls12381.Fr),
	}

	for exp, coeff := range p.coefficients {
		newPoly.coefficients[exp] = bls12381.NewFr().Set(coeff)
	}

	return newPoly
}

// Add adds two polynomials and stores the result in the polynomial the function is being called on.
// It also returns the result as a new polynomial.
func (p *Polynomial) Add(q *Polynomial) *Polynomial {
	for exp, coeff := range q.coefficients {
		if val, ok := p.coefficients[exp]; ok {
			val.Add(val, coeff)
			if val.IsZero() {
				delete(p.coefficients, exp)
			}
		} else {
			p.coefficients[exp] = bls12381.NewFr().Set(coeff) // Copy coefficient
		}
	}
	return p.Copy()
}

// SparseBigAdd adds a slice of big.Int to a polynomial and stores the result in the polynomial the function is being called on.
// It also returns the result as a new polynomial.
// The length of the slice must be equal to the number of coefficients of the polynomial.
func (p *Polynomial) SparseBigAdd(b []*big.Int) (*Polynomial, error) {
	if len(b) != len(p.coefficients) {
		return nil, fmt.Errorf("length of b must be equal to the number of coefficients of the polynomial")
	}

	i := 0
	for _, coeff := range p.coefficients {
		coeff.Add(coeff, bls12381.NewFr().FromBytes(b[i].Bytes()))
		i++
	}

	return p.Copy(), nil
}

// Sub subtracts two polynomials and stores the result in the polynomial the function is being called on.
// It also returns the result as a new polynomial.
func (p *Polynomial) Sub(q *Polynomial) *Polynomial {
	for exp, coeff := range q.coefficients {
		if val, ok := p.coefficients[exp]; ok {
			val.Sub(val, coeff)
			if val.IsZero() {
				delete(p.coefficients, exp)
			}
		} else {
			p.coefficients[exp] = bls12381.NewFr().Set(coeff) // Copy coefficient
			p.coefficients[exp].Neg(p.coefficients[exp])
		}
	}
	return p.Copy()
}

// MulByConstant multiplies the polynomial by a constant.
// It changes the original polynomial and returns a copy of it.
func (p *Polynomial) MulByConstant(constant *bls12381.Fr) *Polynomial {
	for _, coeff := range p.coefficients {
		coeff.Mul(coeff, constant)
	}
	return p.Copy()
}

// Mul multiplies two polynomials and stores the result in the polynomial the function is being called on.
// It always returns the result as a new polynomial.
func (p *Polynomial) Mul(q *Polynomial) (*Polynomial, error) {
	if len(p.coefficients) > 1024 && len(q.coefficients) > 1024 {
		return p.mulFFT(q)
	} else {
		return p.mulNaive(q), nil
	}
}

// Mul returns the product of two polynomials without modifying the original polynomials.
func Mul(p, q *Polynomial) (*Polynomial, error) {
	copyP := p.Copy() // Ensure that the original polynomials are not modified
	return copyP.Mul(q)
}

// Add returns the sum of two polynomials without modifying the original polynomials.
func Add(p, q *Polynomial) *Polynomial {
	copyP := p.Copy() // Ensure that the original polynomials are not modified
	return copyP.Add(q)
}

// Sub returns the difference of two polynomials without modifying the original polynomials.
func Sub(p, q *Polynomial) *Polynomial {
	copyP := p.Copy() // Ensure that the original polynomials are not modified
	return copyP.Sub(q)
}

// mulNaive multiplies two polynomials using the naive method in O(n^2).
// note that this can be faster for polynomials with a small number of coefficients.
func (p *Polynomial) mulNaive(q *Polynomial) *Polynomial {
	resultCoeffs := make(map[int]*bls12381.Fr) // Create a new map for the result

	for expP, coeffP := range p.coefficients { // Iterate through map of p
		for expQ, coeffQ := range q.coefficients { // Iterate through slice of q. This is more efficient than iterating through map of q.
			if !coeffQ.IsZero() {
				exp := expP + expQ
				product := bls12381.NewFr()
				product.Mul(coeffP, coeffQ)

				if val, ok := resultCoeffs[exp]; ok {
					// Add to the existing value and update the map
					newVal := bls12381.NewFr()
					newVal.Add(val, product)
					resultCoeffs[exp] = newVal
				} else {
					resultCoeffs[exp] = product
				}
			}
		}
	}

	p.coefficients = resultCoeffs // Modify the original polynomial
	return p.Copy()
}

// mulFFT multiplies two polynomials using the FFT  in O(nlogn).
// note that this can be faster for polynomials with a very large number of coefficients.
func (p *Polynomial) mulFFT(q *Polynomial) (*Polynomial, error) {
	coeffsP := polyAsCoefficientsBigInt(p)
	coeffsQ := polyAsCoefficientsBigInt(q)
	coeffsP, coeffsQ = extendSliceWithZeros(coeffsP, coeffsQ)

	n := math.Ceil(math.Log2(float64(len(coeffsP))))
	fft, err := NewBLS12381FFT(int(n))
	if err != nil {
		return nil, err
	}
	resultBig, err := fft.MulPolysFFT(coeffsP, coeffsQ)
	if err != nil {
		return nil, err
	}

	// Modify the original polynomial and return a copy of it.
	result := NewFromBig(resultBig)
	p.coefficients = result.Copy().coefficients
	return result, nil
}

// polyAsCoefficients returns the coefficients of the polynomial in the form of a slice.
// The index of the element will be its exponent.
// Zero coefficients are also represented s.t. the full polynomial is represented by the slice.
func polyAsCoefficients(p *Polynomial) []*bls12381.Fr {
	degree, _ := p.Degree()
	coefficients := make([]*bls12381.Fr, degree+1)
	for i := 0; i < degree+1; i++ {
		val, ok := p.coefficients[i]
		if ok {
			coefficients[i] = bls12381.NewFr().Set(val)
		} else {
			coefficients[i] = bls12381.NewFr().Zero()
		}
	}

	return coefficients
}

// polyAsCoefficientsBigInt returns the coefficients of the polynomial in the form of a slice.
// The index of the element will be its exponent.
// Zero coefficients are also represented s.t. the full polynomial is represented by the slice.
func polyAsCoefficientsBigInt(p *Polynomial) []*big.Int {
	degree, _ := p.Degree()
	coefficients := make([]*big.Int, degree+1)
	for i := 0; i < degree+1; i++ {
		val, ok := p.coefficients[i]
		if ok {
			coefficients[i] = val.ToBig()
		} else {
			coefficients[i] = big.NewInt(0)
		}
	}

	return coefficients
}

// extendSliceWithZeros extends a slice of *big.Int to match the length of another slice.
// It appends zeros to the end of the shorter slice.
func extendSliceWithZeros(a, b []*big.Int) ([]*big.Int, []*big.Int) {
	lenA, lenB := len(a), len(b)

	// Determine which slice is shorter
	if lenA < lenB {
		// Extend slice a
		for i := lenA; i < lenB; i++ {
			a = append(a, big.NewInt(0))
		}
	} else if lenB < lenA {
		// Extend slice b
		for i := lenB; i < lenA; i++ {
			b = append(b, big.NewInt(0))
		}
	}

	return a, b
}

// hasDuplicates checks if there are duplicates in a slice of *big.Int.
func hasDuplicates(slice []*big.Int) bool {
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

// containsZero checks if there is a zero value in a slice of *bls12381.Fr.
func containsZero(slice []*bls12381.Fr) bool {
	for _, num := range slice {
		if num.IsZero() {
			return true // Duplicate found
		}
	}
	return false
}

// maxKey returns the maximum key in a map of int -> *bls12381.Fr.
func maxKey(m map[int]*bls12381.Fr) (int, bool) {
	var max int
	found := false

	for k := range m {
		if !found || k > max {
			max = k
			found = true
		}
	}

	return max, found
}
