package poly

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"math/big"
	"math/rand"
	"testing"
)

func TestNewPoly(t *testing.T) {
	slice := randomFrSlice(100)
	poly := NewFromFr(slice)

	assert.Equal(t, len(slice), len(poly.Coefficients))
}

func TestEqual(t *testing.T) {
	slice := randomFrSlice(100)
	poly1 := NewFromFr(slice)
	poly2 := NewFromFr(slice)

	assert.True(t, poly1.Equal(poly2))

	poly3 := NewFromFr(randomFrSlice(100))
	assert.False(t, poly1.Equal(poly3))
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
		assert.Equal(t, expected[i], result.Coefficients[i])
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
		assert.Equal(t, expected[i], result.Coefficients[i])
	}
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
		assert.Equal(t, slice1[i], result.Coefficients[i])
	}
}

func TestMulPolysNaive(t *testing.T) {
	n := 5
	// Test polynomial a: 12x^4 + 25x^3 + 4x^2 + 17
	aValues := []*big.Int{big.NewInt(12), big.NewInt(25), big.NewInt(4), big.NewInt(0), big.NewInt(17)}

	aFr := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		aFr[i] = bls12381.NewFr()
		aFr[i].FromBytes(aValues[i].Bytes())
	}
	aPoly := NewFromFr(aFr)

	// Test polynomial b: 84x^4 + 45x
	bValues := []*big.Int{big.NewInt(84), big.NewInt(0), big.NewInt(0), big.NewInt(45), big.NewInt(0)}

	bFr := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		bFr[i] = bls12381.NewFr()
		bFr[i].FromBytes(bValues[i].Bytes())
	}
	bPoly := NewFromFr(bFr)

	multPolys, err := aPoly.MulNaive(bPoly)
	assert.Nil(t, err)
	assert.NotNil(t, multPolys)
	// Expected result: 1008x^8 + 2100x^7 + 336x^6 + 540x^5 + 2553x^4 + 180x^3 + 765x
	expectedValues := []*big.Int{big.NewInt(1008), big.NewInt(2100), big.NewInt(336), big.NewInt(540), big.NewInt(2553), big.NewInt(180), big.NewInt(0), big.NewInt(765), big.NewInt(0)}
	assert.Equal(t, len(expectedValues), len(multPolys.Coefficients))

	for i := 0; i < len(expectedValues); i++ {
		assert.True(t, expectedValues[i].Cmp(multPolys.Coefficients[i].ToBig()) == 0)
	}
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

func TestFTT(t *testing.T) {
	n := 6
	// Test polynomial a: 12x^4 + 25x^3 + 4x^2 + 17
	aValues := []*big.Int{big.NewInt(12), big.NewInt(25), big.NewInt(4), big.NewInt(0), big.NewInt(17), big.NewInt(17)}

	aFr := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		aFr[i] = bls12381.NewFr()
		aFr[i].FromBytes(aValues[i].Bytes())
	}
	aPoly := NewFromFr(aFr)

	// Test polynomial b: 84x^4 + 45x
	bValues := []*big.Int{big.NewInt(84), big.NewInt(0), big.NewInt(0), big.NewInt(45), big.NewInt(0), big.NewInt(17)}

	bFr := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		bFr[i] = bls12381.NewFr()
		bFr[i].FromBytes(bValues[i].Bytes())
	}
	bPoly := NewFromFr(bFr)

	modulus, _ := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	rootOfUnity, _ := new(big.Int).SetString("5bf3adda19e9b27b0af53ae352a31e645b1b4c801819d7ecb9b58d8c5f0e466a", 16)

	fft := NewFFT(modulus, rootOfUnity)
	mult := fft.MulPolysFFT(aPoly.ToBig(), bPoly.ToBig())

	result := NewFromBig(mult)
	// Expected result: 1008x^8 + 2100x^7 + 336x^6 + 540x^5 + 2553x^4 + 180x^3 + 765x
	expectedValues := []*big.Int{big.NewInt(1008), big.NewInt(2100), big.NewInt(336), big.NewInt(540), big.NewInt(2553), big.NewInt(180), big.NewInt(0), big.NewInt(765), big.NewInt(0)}
	assert.Equal(t, len(expectedValues), len(result.Coefficients))
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

func BenchmarkMulNaiveN20(b *testing.B) { benchmarkMulNaive(b, 512) }

func benchmarkMulNaive(b *testing.B, n int) {
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)
	slice2 := randomFrSlice(n)
	poly2 := NewFromFr(slice2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := poly1
		_, err := p.MulNaive(poly2)
		if err != nil {
			b.Fatal(err)
		}
	}
}
