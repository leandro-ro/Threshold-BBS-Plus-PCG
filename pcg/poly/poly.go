package poly

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math"
	"math/big"
	"math/rand"
	"sync"
)

// Polynomial represents a polynomial in the form of a map: exponent -> coefficient.
type Polynomial struct {
	coefficients map[int]*bls12381.Fr // coefficients of the polynomial in the form of a map: exponent -> coefficient
	mtx          sync.Mutex           // Mutex to ensure thread-safety
}

// NewFromFr converts slice of *bls12381.Fr to Polynomial representation.
// The index of the element will be its exponent.
func NewFromFr(values []*bls12381.Fr) *Polynomial {
	coefficients := make(map[int]*bls12381.Fr)
	for i, v := range values {
		// Ensure that only non-zero coefficients are stored for efficiency.
		if !v.IsZero() {
			coefficients[i] = bls12381.NewFr()
			val := bls12381.NewFr().FromBytes(v.ToBytes()) // Copy coefficient
			coefficients[i].Set(val)
		}
	}

	return &Polynomial{
		coefficients: coefficients,
		mtx:          sync.Mutex{},
	}
}

// NewFromBig converts slice of *big.Int to Polynomial representation.
// The index of the element will be its exponent.
func NewFromBig(values []*big.Int) *Polynomial {
	rValues := make([]*bls12381.Fr, len(values))
	for i, value := range values {
		// Do not check for zero values here, as NewFromFr will do.
		rValues[i] = bls12381.NewFr()
		val := bls12381.NewFr().FromBytes(value.Bytes())
		rValues[i].Set(val)
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
		return nil, fmt.Errorf("exponents must be unique")
	}

	p := &Polynomial{
		coefficients: make(map[int]*bls12381.Fr),
		mtx:          sync.Mutex{},
	}

	for i, c := range coefficients {
		// Ensure that only non-zero coefficients are stored for efficiency.
		if !c.IsZero() {
			index := int(exponents[i].Int64())
			p.coefficients[index] = bls12381.NewFr()
			val := bls12381.NewFr().FromBytes(c.ToBytes())
			p.coefficients[index].Set(val)
		}
	}

	return p, nil
}

// New returns a new empty polynomial.
func New() *Polynomial {
	return &Polynomial{
		coefficients: make(map[int]*bls12381.Fr),
		mtx:          sync.Mutex{},
	}
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
	p.mtx.Lock()
	q.mtx.Lock()
	if len(p.coefficients) != len(q.coefficients) { // Quick check
		return false
	}

	for exp, coeff := range p.coefficients {
		if val, ok := q.coefficients[exp]; !ok || !val.Equal(coeff) {
			return false
		}
	}

	p.mtx.Unlock()
	q.mtx.Unlock()
	return true
}

// Copy returns a copy of the polynomial the function is being called on.
func (p *Polynomial) Copy() *Polynomial {
	newPoly := &Polynomial{
		coefficients: make(map[int]*bls12381.Fr),
		mtx:          sync.Mutex{},
	}

	p.mtx.Lock()
	for exp, coeff := range p.coefficients {
		val := bls12381.NewFr().FromBytes(coeff.ToBytes())
		newPoly.coefficients[exp] = bls12381.NewFr().Set(val)
	}
	p.mtx.Unlock()
	return newPoly
}

// Set sets the polynomial to the polynomial given as argument.
// It is not a copy, so be careful when using this function.
func (p *Polynomial) Set(q *Polynomial) {
	p.mtx.Lock()
	q.mtx.Lock()
	p.coefficients = q.coefficients
	p.mtx.Unlock()
	q.mtx.Unlock()
}

// AmountOfCoefficients returns the number of coefficients of the polynomial.
func (p *Polynomial) AmountOfCoefficients() int {
	return len(p.coefficients)
}

func (p *Polynomial) String() string {
	p.mtx.Lock()
	degree, _ := p.Degree()
	str := ""
	for i := degree; i >= 0; i-- {
		if val, ok := p.coefficients[i]; ok {
			str += fmt.Sprintf("%s*x^%d + ", val.ToBig().String(), i)
		}
	}
	p.mtx.Unlock()
	return str[:len(str)-3] // Remove trailing " + "
}

// Add adds two polynomials and stores the result in the polynomial the function is being called on.
func (p *Polynomial) Add(q *Polynomial) {
	p.mtx.Lock()
	q.mtx.Lock()

	for exp, coeff := range q.coefficients {
		if val, ok := p.coefficients[exp]; ok {
			val.Add(val, coeff)
			if val.IsZero() {
				delete(p.coefficients, exp)
			}
		} else {
			p.coefficients[exp] = bls12381.NewFr().FromBytes(coeff.ToBytes())
		}
	}
	p.mtx.Unlock()
	q.mtx.Unlock()
	return
}

// SparseBigAdd adds a slice of big.Int to a polynomial and stores the result in the polynomial the function is being called on.
// The length of the slice must be equal to the number of coefficients of the polynomial.
func (p *Polynomial) SparseBigAdd(b []*big.Int) error {
	p.mtx.Lock()
	if len(b) != len(p.coefficients) {
		return fmt.Errorf("length of b must be equal to the number of coefficients of the polynomial")
	}

	i := 0
	for _, coeff := range p.coefficients {
		coeff.Add(coeff, bls12381.NewFr().FromBytes(b[i].Bytes()))
		i++
	}
	p.mtx.Unlock()
	return nil
}

// Sub subtracts two polynomials and stores the result in the polynomial the function is being called on.
func (p *Polynomial) Sub(q *Polynomial) {
	p.mtx.Lock()
	q.mtx.Lock()
	for exp, coeff := range q.coefficients {
		if val, ok := p.coefficients[exp]; ok {
			val.Sub(val, coeff)
			if val.IsZero() {
				delete(p.coefficients, exp)
			}
		} else {
			p.coefficients[exp] = bls12381.NewFr().FromBytes(coeff.ToBytes()) // Copy coefficient
			p.coefficients[exp].Neg(p.coefficients[exp])
		}
	}
	p.mtx.Unlock()
	q.mtx.Unlock()
}

// MulByConstant multiplies the polynomial by a constant.
func (p *Polynomial) MulByConstant(constant *bls12381.Fr) {
	p.mtx.Lock()
	for _, coeff := range p.coefficients {
		coeff.Mul(coeff, constant)
	}
	p.mtx.Unlock()
}

// Mul multiplies two polynomials and stores the result in the polynomial the function is being called on.
func (p *Polynomial) Mul(q *Polynomial) error {
	if len(p.coefficients) > 1024 && len(q.coefficients) > 1024 {
		return p.mulFFT(q)
	} else {
		return p.mulNaive(q)
	}
}

// Mul returns the product of two polynomials without modifying the original polynomials.
func Mul(p, q *Polynomial) (*Polynomial, error) {
	copyP := p.Copy() // Ensure that the original polynomials are not modified
	copyQ := q.Copy()

	err := copyP.Mul(copyQ)
	return copyP, err
}

// Add returns the sum of two polynomials without modifying the original polynomials.
func Add(p, q *Polynomial) *Polynomial {
	res := p.Copy() // Ensure that the original polynomials are not modified
	copyQ := q.Copy()
	res.Add(copyQ)
	return res
}

// Sub returns the difference of two polynomials without modifying the original polynomials.
func Sub(p, q *Polynomial) *Polynomial {
	res := p.Copy() // Ensure that the original polynomials are not modified
	copyQ := q.Copy()
	res.Sub(copyQ)
	return res
}

// Sparseness returns the sparseness of the polynomial.
// It returns the number of non-zero coefficients.
// E.g. x^2 + 2 = 1*x^2 + 0*x^1 + 2*x^0 -> 2 non-zero coefficients, hence 2-sparse.
func (p *Polynomial) Sparseness() int {
	degree, err := p.Degree()
	if err != nil {
		return 0
	}
	return degree + 1 - len(p.coefficients) // +1 as we need to also account for the constant term, e.g. x^2 + 2 -> (degree: 2) + 1 - (coeff len: 1) = 2 sparse
}

// mulNaive multiplies two polynomials using the naive method in O(n^2).
// note that this can be faster for polynomials with a small number of coefficients.
func (p *Polynomial) mulNaive(q *Polynomial) error {
	resultCoeffs := make(map[int]*bls12381.Fr) // Create a new map for the result

	p.mtx.Lock()
	q.mtx.Lock()
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
	p.coefficients = resultCoeffs
	p.mtx.Unlock()
	q.mtx.Unlock()
	return nil
}

// mulFFT multiplies two polynomials using the FFT  in O(nlogn).
// note that this can be faster for polynomials with a very large number of coefficients.
func (p *Polynomial) mulFFT(q *Polynomial) error {
	p.mtx.Lock()
	q.mtx.Lock()
	coeffsP := polyAsCoefficientsBigInt(p)
	coeffsQ := polyAsCoefficientsBigInt(q)
	coeffsP, coeffsQ = extendSliceWithZeros(coeffsP, coeffsQ)

	n := math.Ceil(math.Log2(float64(len(coeffsP))))
	fft, err := NewBLS12381FFT(int(n))
	if err != nil {
		return err
	}
	resultBig, err := fft.MulPolysFFT(coeffsP, coeffsQ)
	if err != nil {
		return err
	}

	p.coefficients = NewFromBig(resultBig).coefficients
	p.mtx.Unlock()
	q.mtx.Unlock()
	return nil
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
