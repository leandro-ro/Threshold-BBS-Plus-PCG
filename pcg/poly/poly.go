package poly

import (
	"bytes"
	"encoding/binary"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"log"
	"math"
	"math/big"
	"math/rand"
)

// Polynomial represents a polynomial in the form of a map: exponent -> coefficient.
type Polynomial struct {
	Coefficients map[int]*bls12381.Fr // Coefficients of the polynomial in the form of a map: exponent -> coefficient
}

// Serialize returns the byte representation of the polynomial.
func (p *Polynomial) Serialize() ([]byte, error) {
	var buffer bytes.Buffer

	for exponent, coefficient := range p.Coefficients {
		// Write the exponent
		err := binary.Write(&buffer, binary.BigEndian, int32(exponent))
		if err != nil {
			return nil, err
		}

		// Write the coefficient
		coeffBytes := coefficient.ToBytes()
		buffer.Write(coeffBytes[:])
	}

	return buffer.Bytes(), nil
}

// Deserialize deserializes the byte representation of a polynomial and sets the polynomial the function is being called on.
func (p *Polynomial) Deserialize(data []byte) error {
	buffer := bytes.NewBuffer(data)
	var exponent int32
	newPolynomial := &Polynomial{Coefficients: make(map[int]*bls12381.Fr)}

	for buffer.Len() > 0 {
		// Read the exponent
		err := binary.Read(buffer, binary.BigEndian, &exponent)
		if err != nil {
			return err
		}

		// Read the coefficient
		coeffBytes := make([]byte, 32) // size of bls12381.Fr in bytes is 32
		_, err = buffer.Read(coeffBytes)
		if err != nil {
			return err
		}
		coefficient := bls12381.NewFr()
		coefficient.FromBytes(coeffBytes)

		newPolynomial.Coefficients[int(exponent)] = coefficient
	}

	p.Set(newPolynomial)
	return nil
}

// NewEmpty returns a new empty polynomial.
func NewEmpty() *Polynomial {
	return &Polynomial{
		Coefficients: make(map[int]*bls12381.Fr),
	}
}

// NewFromSerialization takes a serialized polynomial and deserializes it to return a new Polynomial.
func NewFromSerialization(data []byte) (*Polynomial, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("byte slice is empty")
	}
	newPoly := NewEmpty()
	err := newPoly.Deserialize(data)
	if err != nil {
		return nil, err
	}
	return newPoly, nil
}

// NewFromFr converts slice of *bls12381.Fr to Polynomial representation.
// The index of the element will be its exponent.
func NewFromFr(values []*bls12381.Fr) *Polynomial {
	coefficients := make(map[int]*bls12381.Fr)
	for i, v := range values {
		// Ensure that only non-zero Coefficients are stored for efficiency.
		if !v.IsZero() {
			coefficients[i] = bls12381.NewFr()
			val := bls12381.NewFr().FromBytes(v.ToBytes()) // DeepCopy coefficient
			coefficients[i].Set(val)
		}
	}

	return &Polynomial{
		Coefficients: coefficients,
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

// NewSparse creates a new sparse polynomial with the given Coefficients and their exponents.
// The index of the coefficient will determine the respective exponent in the exponents slice.
// E.g. Coefficients = [1, 2, 3], exponents = [0, 1, 2] -> 1*x^0 + 2*x^1 + 3*x^2
func NewSparse(coefficients []*bls12381.Fr, exponents []*big.Int) (*Polynomial, error) {
	if len(coefficients) != len(exponents) {
		return nil, fmt.Errorf("length of Coefficients and exponents must be equal")
	}
	if hasDuplicates(exponents) {
		return nil, fmt.Errorf("exponents must be unique")
	}

	p := &Polynomial{
		Coefficients: make(map[int]*bls12381.Fr),
	}

	for i, c := range coefficients {
		// Ensure that only non-zero Coefficients are stored for efficiency.
		if !c.IsZero() {
			index := int(exponents[i].Int64())
			p.Coefficients[index] = bls12381.NewFr()
			val := bls12381.NewFr().FromBytes(c.ToBytes())
			p.Coefficients[index].Set(val)
		}
	}

	return p, nil
}

// NewRandomPolynomial creates a random polynomial of the given degree.
// Every coefficient is a random element in Fr, hence the polynomial is most likely not sparse.
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

// NewCyclotomicPolynomial creates a cyclotomic polynomial of the given degree.
// The resulting polynomial will have the following structure: x^degree + neg(1)
func NewCyclotomicPolynomial(degree *big.Int) (*Polynomial, error) {
	if degree.Cmp(big.NewInt(0)) < 0 {
		return nil, fmt.Errorf("degree must be greater than zero")
	}
	one := bls12381.NewFr().One()
	poly := NewEmpty()
	poly.Coefficients[0] = bls12381.NewFr()
	poly.Coefficients[0].Neg(one)
	poly.Coefficients[int(degree.Int64())] = bls12381.NewFr().One()

	return poly, nil
}

// Degree returns the degree of the polynomial.
// If the polynomial is empty, it returns an error.
func (p *Polynomial) Degree() (int, error) {
	deg, found := maxKey(p.Coefficients)
	if !found {
		return -1, fmt.Errorf("polynomial is empty")
	}
	return deg, nil
}

// Equal checks if two polynomials are equal.
func (p *Polynomial) Equal(q *Polynomial) bool {
	if len(p.Coefficients) != len(q.Coefficients) { // Quick check
		return false
	}

	for exp, coeff := range p.Coefficients {
		if val, ok := q.Coefficients[exp]; !ok || !val.Equal(coeff) {
			return false
		}
	}

	return true
}

// DeepCopy returns a copy of the polynomial the function is being called on.
func (p *Polynomial) DeepCopy() *Polynomial {
	newPoly := &Polynomial{
		Coefficients: make(map[int]*bls12381.Fr),
	}

	for exp, coeff := range p.Coefficients {
		val := bls12381.NewFr().FromBytes(coeff.ToBytes())
		newPoly.Coefficients[exp] = bls12381.NewFr().Set(val)
	}

	return newPoly
}

// Set sets the polynomial to the polynomial given as argument.
// It is not a copy, so be careful when using this function.
func (p *Polynomial) Set(q *Polynomial) {
	p.Coefficients = q.Coefficients
}

// AmountOfCoefficients returns the number of Coefficients of the polynomial.
func (p *Polynomial) AmountOfCoefficients() int {
	return len(p.Coefficients)
}

// String returns the string representation of the polynomial.
func (p *Polynomial) String() string {
	degree, _ := p.Degree()
	str := ""
	for i := degree; i >= 0; i-- {
		if val, ok := p.Coefficients[i]; ok {
			str += fmt.Sprintf("%s*x^%d + ", val.ToBig().String(), i)
		}
	}
	return str[:len(str)-3] // Remove trailing " + "
}

// Add adds two polynomials and stores the result in the polynomial the function is being called on.
func (p *Polynomial) Add(q *Polynomial) {
	for exp, coeff := range q.Coefficients {
		if val, ok := p.Coefficients[exp]; ok {
			val.Add(val, coeff)
			if val.IsZero() {
				delete(p.Coefficients, exp)
			}
		} else {
			p.Coefficients[exp] = bls12381.NewFr().FromBytes(coeff.ToBytes())
		}
	}
	return
}

// SparseBigAdd adds a slice of big.Int to a polynomial and stores the result in the polynomial the function is being called on.
// The length of the slice must be equal to the number of Coefficients of the polynomial.
func (p *Polynomial) SparseBigAdd(b []*big.Int) error {
	if len(b) != len(p.Coefficients) {
		return fmt.Errorf("length of b must be equal to the number of Coefficients of the polynomial")
	}

	i := 0
	for _, coeff := range p.Coefficients {
		valFr := bls12381.NewFr().FromBytes(coeff.ToBytes())
		coeff.Add(coeff, valFr)
		i++
	}
	return nil
}

// Sub subtracts two polynomials and stores the result in the polynomial the function is being called on.
func (p *Polynomial) Sub(q *Polynomial) {
	for exp, coeff := range q.Coefficients {
		if val, ok := p.Coefficients[exp]; ok {
			val.Sub(val, coeff)
			if val.IsZero() {
				delete(p.Coefficients, exp)
			}
		} else {
			p.Coefficients[exp] = bls12381.NewFr().FromBytes(coeff.ToBytes()) // DeepCopy coefficient
			p.Coefficients[exp].Neg(p.Coefficients[exp])
		}
	}
}

// MulByConstant multiplies the polynomial by a constant.
func (p *Polynomial) MulByConstant(constant *bls12381.Fr) {
	for _, coeff := range p.Coefficients {
		coeff.Mul(coeff, constant)
	}
}

// Mul multiplies two polynomials and stores the result in the polynomial the function is being called on.
// The function will choose the most efficient method of multiplication depending on the structure of the polynomials.
func (p *Polynomial) Mul(q *Polynomial) error {
	maxComplexity := len(p.Coefficients) * len(q.Coefficients)
	if maxComplexity < 512 {
		return p.mulNaive(q)
	}

	// Calculate the degrees of the polynomials
	degP, err := p.Degree()
	if err != nil {
		return err
	}
	degQ, err := q.Degree()
	if err != nil {
		return err
	}

	// Calculate the size for FFT, which is the next power of 2 greater than degP + degQ
	nFFT := nextPowerOf2(degP + degQ + 1)

	// Compare the product of non-zero coefficients with nFFT * log2(nFFT)
	if maxComplexity > nFFT*log2(nFFT) {
		log.Println("Multiplying using FFT")
		return p.mulFFT(q)
	} else {
		return p.mulNaive(q)
	}
}

// Mul returns the product of two polynomials without modifying the original polynomials.
func Mul(p, q *Polynomial) (*Polynomial, error) {
	copyP := p.DeepCopy() // Ensure that the original polynomials are not modified
	copyQ := q.DeepCopy()

	err := copyP.Mul(copyQ)
	return copyP, err
}

// Add returns the sum of two polynomials without modifying the original polynomials.
func Add(p, q *Polynomial) *Polynomial {
	res := p.DeepCopy() // Ensure that the original polynomials are not modified
	copyQ := q.DeepCopy()
	res.Add(copyQ)
	return res
}

// Sub returns the difference of two polynomials without modifying the original polynomials.
func Sub(p, q *Polynomial) *Polynomial {
	res := p.DeepCopy() // Ensure that the original polynomials are not modified
	copyQ := q.DeepCopy()
	res.Sub(copyQ)
	return res
}

// GetCoefficient returns the coefficient of the given exponent.
func (p *Polynomial) GetCoefficient(i int) (*bls12381.Fr, error) {
	if val, ok := p.Coefficients[i]; ok {
		ret := bls12381.NewFr().FromBytes(val.ToBytes()) // DeepCopy coefficient
		return ret, nil
	} else {
		return nil, fmt.Errorf("coefficient does not exist")
	}
}

// Evaluate evaluates the polynomial at the given point x.
func (p *Polynomial) Evaluate(x *bls12381.Fr) *bls12381.Fr {
	result := bls12381.NewFr()
	result.Zero()

	for exp, coeff := range p.Coefficients {
		term := bls12381.NewFr()
		term.Exp(x, big.NewInt(int64(exp)))
		term.Mul(term, coeff)
		result.Add(result, term)
	}

	return result
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
		return p.DeepCopy(), nil
	}

	remainder := p.DeepCopy()
	for currentRemDeg >= divisorDegree {
		leadingTermExponent := currentRemDeg - divisorDegree

		inv := bls12381.NewFr()
		inv.Inverse(divisor.Coefficients[divisorDegree])
		leadingTermCoefficient := bls12381.NewFr()
		leadingTermCoefficient.Mul(remainder.Coefficients[currentRemDeg], inv)

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
		return p.DeepCopy(), nil
	}

	remainder := NewEmpty()
	// Iterate over all Coefficients of p
	for degree, coefficient := range p.Coefficients {
		newDegree := degree % divisorDegree
		if val, ok := remainder.Coefficients[newDegree]; ok {
			// If there is already a coefficient at newDegree, add to it
			val.Add(val, coefficient)
			if val.IsZero() {
				delete(remainder.Coefficients, newDegree)
			}
		} else {
			// Otherwise, set the new coefficient at newDegree
			coeffCopy := bls12381.NewFr().FromBytes(coefficient.ToBytes())
			remainder.Coefficients[newDegree] = bls12381.NewFr()
			remainder.Coefficients[newDegree].Set(coeffCopy)
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
	if val, ok := p.Coefficients[degree]; ok {
		if !val.Equal(one) {
			return false
		}
	} else {
		return false
	}
	if val, ok := p.Coefficients[0]; ok {
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
// note that this can be faster for polynomials with a small number of Coefficients.
func (p *Polynomial) mulNaive(q *Polynomial) error {
	resultCoeffs := make(map[int]*bls12381.Fr) // Create a new map for the result

	for expP, coeffP := range p.Coefficients { // Iterate through map of p
		for expQ, coeffQ := range q.Coefficients { // Iterate through slice of q. This is more efficient than iterating through map of q.
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
	p.Coefficients = resultCoeffs
	return nil
}

// mulFFT multiplies two polynomials using the FFT  in O(nlogn).
// note that this can be faster for polynomials with a very large number of Coefficients.
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

	p.Coefficients = NewFromBig(resultBig).Coefficients
	return nil
}

// polyAsCoefficientsBigInt returns the Coefficients of the polynomial in the form of a slice.
// The index of the element will be its exponent.
// Zero Coefficients are also represented s.t. the full polynomial is represented by the slice.
func polyAsCoefficientsBigInt(p *Polynomial) []*big.Int {
	degree, _ := p.Degree()
	coefficients := make([]*big.Int, degree+1)
	for i := 0; i < degree+1; i++ {
		val, ok := p.Coefficients[i]
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

// Helper function to calculate the next power of 2
func nextPowerOf2(n int) int {
	if n <= 0 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	return n + 1
}

// Helper function to calculate log base 2 of an integer
func log2(n int) int {
	log := 0
	for n > 1 {
		n /= 2
		log++
	}
	return log
}
