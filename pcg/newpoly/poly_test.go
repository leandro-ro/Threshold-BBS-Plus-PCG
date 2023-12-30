package newpoly

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestNewPoly(t *testing.T) {
	slice := randomFrSlice(100)
	poly := NewFromFr(slice)

	assert.Equal(t, len(slice), len(poly.coefficients))
}

func TestNewSparsePoly(t *testing.T) {
	sparseT := 4
	maxExp := big.NewInt(127)

	coefficients := randomFrSlice(sparseT)
	exponents := []*big.Int{big.NewInt(2), big.NewInt(9), big.NewInt(8), maxExp}
	poly, err := NewSparse(coefficients, exponents)
	assert.Nil(t, err)

	assert.Equal(t, len(poly.coefficients), len(exponents))
}

func TestEqual(t *testing.T) {
	slice := randomFrSlice(100)
	poly1 := NewFromFr(slice)
	poly2 := NewFromFr(slice)

	assert.True(t, poly1.Equal(poly2))

	poly3 := NewFromFr(randomFrSlice(100))
	assert.False(t, poly1.Equal(poly3))
}

func TestCopy(t *testing.T) {
	slice := randomFrSlice(100)
	poly1 := NewFromFr(slice)

	poly2 := poly1.Copy()
	assert.True(t, poly1.Equal(poly2))

	sparseT := 16
	maxExp := big.NewInt(127)

	coefficientsA := randomFrSlice(sparseT)
	exponentsA := randomBigIntSlice(sparseT, maxExp)
	exponentsA[sparseT-1].Set(big.NewInt(128)) // Ensure equal degree.
	polyA, err := NewSparse(coefficientsA, exponentsA)
	assert.Nil(t, err)

	polyB := polyA.Copy()
	assert.True(t, polyA.Equal(polyB))
}

func TestAddPolys(t *testing.T) {
	n := 512
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)

	slice2 := randomFrSlice(n)
	poly2 := NewFromFr(slice2)

	expected := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		e := bls12381.NewFr()
		e.Add(slice1[i], slice2[i])
		expected[i] = bls12381.NewFr()
		expected[i].Set(e)
	}

	result := poly1.Add(poly2)
	for i := 0; i < n; i++ {
		assert.Equal(t, expected[i], result.coefficients[i])
	}
}

func TestSubPolys(t *testing.T) {
	n := 512
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)

	slice2 := randomFrSlice(n)
	poly2 := NewFromFr(slice2)

	expected := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		e := bls12381.NewFr()
		e.Sub(slice1[i], slice2[i])
		expected[i] = bls12381.NewFr()
		expected[i].Set(e)
	}

	result := poly1.Sub(poly2)
	for i := 0; i < n; i++ {
		assert.Equal(t, expected[i], result.coefficients[i])
	}
}

func TestSubEqual(t *testing.T) {
	n := 512
	slice := randomFrSlice(n)
	poly1 := NewFromFr(slice)
	poly2 := NewFromFr(slice)

	expected := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		e := bls12381.NewFr()
		e.Sub(slice[i], slice[i])
		expected[i] = bls12381.NewFr()
		expected[i].Set(e)
	}

	result := poly1.Sub(poly2) // should be zero
	emptyPoly := &Polynomial{}
	assert.True(t, result.Equal(emptyPoly))
}

func TestAddSubPolys(t *testing.T) {
	n := 512
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)

	slice2 := randomFrSlice(n)
	poly2 := NewFromFr(slice2)

	poly1.Add(poly2)
	result := poly1.Sub(poly2)

	for i := 0; i < n; i++ {
		assert.Equal(t, slice1[i], result.coefficients[i])
	}
}

func TestMulPolysNaive(t *testing.T) {
	// Test polynomial a: 12x^4 + 25x^3 + 4x^2 + 17
	aValues := []*big.Int{big.NewInt(17), big.NewInt(0), big.NewInt(4), big.NewInt(25), big.NewInt(12)}
	aPoly := NewFromBig(aValues)

	// Test polynomial b: 84x^4 + 45x
	bValues := []*big.Int{big.NewInt(0), big.NewInt(45), big.NewInt(0), big.NewInt(0), big.NewInt(84)}
	bPoly := NewFromBig(bValues)

	result := aPoly.mulNaive(bPoly)
	assert.NotNil(t, result)

	// Expected result: 1008x^8 + 2100x^7 + 336x^6 + 540x^5 + 2553x^4 + 180x^3 + 765x
	expectedValues := []*big.Int{big.NewInt(0), big.NewInt(765), big.NewInt(0), big.NewInt(180), big.NewInt(2553), big.NewInt(540), big.NewInt(336), big.NewInt(2100), big.NewInt(1008)}
	expected := NewFromBig(expectedValues)

	assert.Equal(t, len(expected.coefficients), len(result.coefficients))
	assert.True(t, expected.Equal(result))
}

func TestMulPolyByConstant(t *testing.T) {
	n := 512
	slice := randomFrSlice(n)
	poly := NewFromFr(slice)

	constant := bls12381.NewFr()
	constant.FromBytes(big.NewInt(42).Bytes())

	expected := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		e := bls12381.NewFr()
		e.Mul(slice[i], constant)
		expected[i] = bls12381.NewFr()
		expected[i].Set(e)
	}
	expectedPoly := NewFromFr(expected)

	result := poly.MulByConstant(constant)
	assert.True(t, expectedPoly.Equal(result))
}

func randomFrSlice(n int) []*bls12381.Fr {
	slice := make([]*bls12381.Fr, n)

	rng := rand.New(rand.NewSource(rand.Int63()))
	for i := range slice {
		randVal := bls12381.NewFr()
		slice[i] = bls12381.NewFr()
		fr, _ := randVal.Rand(rng)
		slice[i].Set(fr)
	}
	return slice
}

// randomBigIntSlice generates a slice of random *big.Int values.
func randomBigIntSlice(n int, max *big.Int) []*big.Int {
	slice := make([]*big.Int, n)
	seen := make(map[string]bool)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < n; i++ {
		for {
			randNum := new(big.Int).Rand(rng, max)
			numStr := randNum.String()

			if !seen[numStr] {
				slice[i] = randNum
				seen[numStr] = true
				break
			}
		}
	}

	return slice
}
