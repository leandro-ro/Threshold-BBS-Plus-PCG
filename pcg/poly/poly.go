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
			coefficients[i] = bls12381.NewFr()
			val := bls12381.NewFr().FromBytes(v.ToBytes()) // Copy coefficient
			coefficients[i].Set(val)
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

// NewCyclotomicPolynomial creates a polynomial of the following structure:
// x^degree + neg(1)
func NewCyclotomicPolynomial(degree *big.Int) (*Polynomial, error) {
	if degree.Cmp(big.NewInt(0)) < 0 {
		return nil, fmt.Errorf("degree must be greater than zero")
	}
	one := bls12381.NewFr().One()
	poly := New()
	poly.coefficients[0] = bls12381.NewFr()
	poly.coefficients[0].Neg(one)
	poly.coefficients[int(degree.Int64())] = bls12381.NewFr().One()

	return poly, nil
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
		val := bls12381.NewFr().FromBytes(coeff.ToBytes())
		newPoly.coefficients[exp] = bls12381.NewFr().Set(val)
	}

	return newPoly
}

// Set sets the polynomial to the polynomial given as argument.
// It is not a copy, so be careful when using this function.
func (p *Polynomial) Set(q *Polynomial) {
	p.coefficients = q.coefficients
}

// AmountOfCoefficients returns the number of coefficients of the polynomial.
func (p *Polynomial) AmountOfCoefficients() int {
	return len(p.coefficients)
}

func (p *Polynomial) String() string {
	degree, _ := p.Degree()
	str := ""
	for i := degree; i >= 0; i-- {
		if val, ok := p.coefficients[i]; ok {
			str += fmt.Sprintf("%s*x^%d + ", val.ToBig().String(), i)
		}
	}
	return str[:len(str)-3] // Remove trailing " + "
}

// Add adds two polynomials and stores the result in the polynomial the function is being called on.
func (p *Polynomial) Add(q *Polynomial) {
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
	return
}

// SparseBigAdd adds a slice of big.Int to a polynomial and stores the result in the polynomial the function is being called on.
// The length of the slice must be equal to the number of coefficients of the polynomial.
func (p *Polynomial) SparseBigAdd(b []*big.Int) error {
	if len(b) != len(p.coefficients) {
		return fmt.Errorf("length of b must be equal to the number of coefficients of the polynomial")
	}

	i := 0
	for _, coeff := range p.coefficients {
		coeff.Add(coeff, bls12381.NewFr().FromBytes(b[i].Bytes()))
		i++
	}
	return nil
}

// Sub subtracts two polynomials and stores the result in the polynomial the function is being called on.
func (p *Polynomial) Sub(q *Polynomial) {
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
}

// MulByConstant multiplies the polynomial by a constant.
func (p *Polynomial) MulByConstant(constant *bls12381.Fr) {
	for _, coeff := range p.coefficients {
		coeff.Mul(coeff, constant)
	}
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

// Mod returns the remainder of the polynomial divided by another polynomial.
func (p *Polynomial) Mod(divisor *Polynomial) (*Polynomial, error) {
	if p.isCyclotomic() { // Optimization for cyclotomic polynomials
		return p.modCyclotomic(divisor)
	} else {
		return p.modNaive(divisor)
	}
}

// modNaive returns the remainder of the polynomial divided by another polynomial.
// This is the naive method of modulo using polynomial division.
func (p *Polynomial) modNaive(divisor *Polynomial) (*Polynomial, error) {
	divisorDegree, err := divisor.Degree()
	if err != nil {
		return nil, err
	}
	currentRemDeg, err := p.Degree()
	if err != nil {
		return nil, err
	}
	// Quick check if the degree of the divisor is greater than the dividend
	if divisorDegree > currentRemDeg {
		return p.Copy(), nil
	}

	remainder := p.Copy()
	for currentRemDeg >= divisorDegree {
		leadingTermExponent := currentRemDeg - divisorDegree

		inv := bls12381.NewFr()
		inv.Inverse(divisor.coefficients[divisorDegree])
		leadingTermCoefficient := bls12381.NewFr()
		leadingTermCoefficient.Mul(remainder.coefficients[currentRemDeg], inv)

		monomial, err := NewSparse([]*bls12381.Fr{leadingTermCoefficient}, []*big.Int{big.NewInt(int64(leadingTermExponent))})
		if err != nil {
			return nil, err
		}
		otherMulMonomial, err := Mul(divisor, monomial)
		if err != nil {
			return nil, err
		}
		remainder.Sub(otherMulMonomial)
		currentRemDeg, err = remainder.Degree()
		if err != nil {
			return nil, err
		}
	}

	return remainder, nil
}

// modCyclotomic performs a modulo operation on a polynomial with a cyclotomic polynomial.
// This is an optimization for the modulo operation as we do not need to perform polynomial multiplication.
func (p *Polynomial) modCyclotomic(divisor *Polynomial) (*Polynomial, error) {
	if !divisor.isCyclotomic() {
		return nil, fmt.Errorf("the divisor must be a cyclotomic polynomial")
	}

	divisorDegree, err := divisor.Degree()
	if err != nil {
		return nil, err
	}
	currentRemDeg, err := p.Degree()
	if err != nil {
		return nil, err
	}

	// Quick check if the degree of the divisor is greater than the dividend
	if divisorDegree > currentRemDeg {
		return p.Copy(), nil
	}

	remainder := New()
	// Iterate over all coefficients of p
	for degree, coefficient := range p.coefficients {
		newDegree := degree % divisorDegree
		if val, ok := remainder.coefficients[newDegree]; ok {
			// If there is already a coefficient at newDegree, add to it
			val.Add(val, coefficient)
			if val.IsZero() {
				delete(remainder.coefficients, newDegree)
			}
		} else {
			// Otherwise, set the new coefficient at newDegree
			coeffCopy := bls12381.NewFr().FromBytes(coefficient.ToBytes())
			remainder.coefficients[newDegree] = bls12381.NewFr()
			remainder.coefficients[newDegree].Set(coeffCopy)
		}
	}

	return remainder, nil
}

// isCyclotomic checks if the polynomial is a cyclotomic polynomial.
// A cyclotomic polynomial is of the form x^n + neg(1).
func (p *Polynomial) isCyclotomic() bool {
	degree, err := p.Degree()
	if err != nil {
		return false
	}
	if degree == 0 {
		return false
	}

	one := bls12381.NewFr().One()
	if val, ok := p.coefficients[degree]; ok {
		if !val.Equal(one) {
			return false
		}
	} else {
		return false
	}
	if val, ok := p.coefficients[0]; ok {
		oneNeg := bls12381.NewFr()
		oneNeg.Neg(one)
		if !val.Equal(oneNeg) {
			return false
		}
	} else {
		return false
	}

	return true
}

// mulNaive multiplies two polynomials using the naive method in O(n^2).
// note that this can be faster for polynomials with a small number of coefficients.
func (p *Polynomial) mulNaive(q *Polynomial) error {
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
	p.coefficients = resultCoeffs
	return nil
}

// mulFFT multiplies two polynomials using the FFT  in O(nlogn).
// note that this can be faster for polynomials with a very large number of coefficients.
func (p *Polynomial) mulFFT(q *Polynomial) error {
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

// maxKey returns the maximum key in a map of int -> *bls12381.Fr.
func maxKey(m map[int]*bls12381.Fr) (int, bool) {
	var maxEx int
	found := false

	for k := range m {
		if !found || k > maxEx {
			maxEx = k
			found = true
		}
	}

	return maxEx, found
}
