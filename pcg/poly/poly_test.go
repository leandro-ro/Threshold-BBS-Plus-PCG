package poly

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

	assert.Equal(t, len(slice), len(poly.Coefficients))
}

func TestSerialize(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	poly, err := NewRandomPolynomial(rng, 512)
	assert.Nil(t, err)

	serializedBytes, err := poly.Serialize()
	assert.Nil(t, err)
	assert.NotNil(t, serializedBytes)

	deserialized := NewEmpty()
	err = deserialized.Deserialize(serializedBytes)
	assert.Nil(t, err)
	assert.NotNil(t, deserialized)
	assert.True(t, poly.Equal(deserialized))

	fromBytes, err := NewFromSerialization(serializedBytes)
	assert.Nil(t, err)
	assert.NotNil(t, fromBytes)
	assert.True(t, poly.Equal(fromBytes))

}

func TestNewSparsePoly(t *testing.T) {
	sparseT := 4
	maxExp := big.NewInt(127)

	coefficients := randomFrSlice(sparseT)
	exponents := []*big.Int{big.NewInt(2), big.NewInt(9), big.NewInt(8), maxExp}
	poly, err := NewSparse(coefficients, exponents)
	assert.Nil(t, err)

	assert.Equal(t, len(poly.Coefficients), len(exponents))
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

	poly2 := poly1.DeepCopy()
	assert.True(t, poly1.Equal(poly2))

	sparseT := 16
	maxExp := big.NewInt(127)

	coefficientsA := randomFrSlice(sparseT)
	exponentsA := randomBigIntSlice(sparseT, maxExp)
	exponentsA[sparseT-1].Set(big.NewInt(128)) // Ensure equal degree.
	polyA, err := NewSparse(coefficientsA, exponentsA)
	assert.Nil(t, err)

	polyB := polyA.DeepCopy()
	assert.True(t, polyA.Equal(polyB))
}

func TestDegree(t *testing.T) {
	n := 512
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)

	deg, err := poly1.Degree()
	assert.Nil(t, err)
	assert.Equal(t, n-1, deg)
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

	poly1.Add(poly2)
	for i := 0; i < n; i++ {
		assert.Equal(t, expected[i], poly1.Coefficients[i])
	}
}

func TestAddEmpty(t *testing.T) {
	n := 512
	slice := randomFrSlice(n)
	poly1 := NewEmpty()
	poly2 := NewFromFr(slice)

	result := Add(poly1, poly2)
	assert.True(t, poly2.Equal(result))
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

	poly1.Sub(poly2)
	for i := 0; i < n; i++ {
		assert.Equal(t, expected[i], poly1.Coefficients[i])
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

	result := Sub(poly1, poly2) // should be zero
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
	poly1.Sub(poly2)

	for i := 0; i < n; i++ {
		assert.Equal(t, slice1[i], poly1.Coefficients[i])
	}
}

func TestMulPolysNaive(t *testing.T) {
	// Test polynomial a: 12x^4 + 25x^3 + 4x^2 + 17
	aValues := []*big.Int{big.NewInt(17), big.NewInt(0), big.NewInt(4), big.NewInt(25), big.NewInt(12)}
	aPoly := NewFromBig(aValues)

	// Test polynomial b: 84x^4 + 45x
	bValues := []*big.Int{big.NewInt(0), big.NewInt(45), big.NewInt(0), big.NewInt(0), big.NewInt(84)}
	bPoly := NewFromBig(bValues)

	err := aPoly.mulNaive(bPoly)
	assert.Nil(t, err)
	assert.NotNil(t, aPoly)

	// Expected result: 1008x^8 + 2100x^7 + 336x^6 + 540x^5 + 2553x^4 + 180x^3 + 765x
	expectedValues := []*big.Int{big.NewInt(0), big.NewInt(765), big.NewInt(0), big.NewInt(180), big.NewInt(2553), big.NewInt(540), big.NewInt(336), big.NewInt(2100), big.NewInt(1008)}
	expected := NewFromBig(expectedValues)

	assert.Equal(t, len(expected.Coefficients), len(aPoly.Coefficients))
	assert.True(t, expected.Equal(aPoly))
}

func TestEvaluate(t *testing.T) {
	// Test polynomial a: a(x) = 12x^4 + 25x^3 + 4x^2 + 17
	aValues := []*big.Int{big.NewInt(17), big.NewInt(0), big.NewInt(4), big.NewInt(25), big.NewInt(12)}
	aPoly := NewFromBig(aValues)

	x := bls12381.NewFr().FromBytes(big.NewInt(14).Bytes())
	expected := bls12381.NewFr().FromBytes(big.NewInt(530393).Bytes())

	resulta := aPoly.Evaluate(x)
	assert.Equal(t, expected, resulta)

	// Test polynomial b: b(x) = 0
	bPoly := NewEmpty()
	resultb := bPoly.Evaluate(x)
	assert.Equal(t, bls12381.NewFr().Zero(), resultb)

	// Test polynomial c: c(x) = 10x + 10
	ref := big.NewInt(10)
	cPoly := NewFromBig([]*big.Int{ref, ref})
	resultc := cPoly.Evaluate(x)
	expectedResult := bls12381.NewFr().FromBytes(big.NewInt(150).Bytes())
	assert.Equal(t, expectedResult, resultc)

	resultd := cPoly.evaluateNaive(x)
	assert.Equal(t, expectedResult, resultd)
}

func TestEvaluateLarge(t *testing.T) {
	poly := NewFromFr(randomFrSlice(2048))
	x := bls12381.NewFr().FromBytes(big.NewInt(14).Bytes())

	resulta := poly.evaluateSequential(x)
	resultb := poly.Evaluate(x)

	assert.True(t, resulta.Equal(resultb))

	resultd := poly.evaluateParallel(x)
	assert.True(t, resulta.Equal(resultd))
}

func TestSeparateMul(t *testing.T) {
	n := 512
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)
	poly1Expected := poly1.DeepCopy()

	slice2 := randomFrSlice(n)
	poly2 := NewFromFr(slice2)
	poly2Expected := poly2.DeepCopy()

	result1, err := Mul(poly1, poly2)
	assert.Nil(t, err)
	assert.NotNil(t, result1)

	// Check that the original polynomials are not changed.
	assert.True(t, poly1.Equal(poly1Expected))
	assert.True(t, poly2.Equal(poly2Expected))

	// Compare with multiplication on objects.
	err = poly1.Mul(poly2) // result stored in poly1
	assert.Nil(t, err)
	assert.NotNil(t, poly1)

	assert.True(t, result1.Equal(poly1))
	assert.False(t, poly1.Equal(poly1Expected))
	assert.True(t, poly2.Equal(poly2Expected))
}

func TestMulPolysFFT(t *testing.T) {
	// Test polynomial a: 12x^4 + 25x^3 + 4x^2 + 17
	aValues := []*big.Int{big.NewInt(17), big.NewInt(0), big.NewInt(4), big.NewInt(25), big.NewInt(12)}
	aPoly := NewFromBig(aValues)

	// Test polynomial b: 84x^4 + 45x
	bValues := []*big.Int{big.NewInt(0), big.NewInt(45), big.NewInt(0), big.NewInt(0), big.NewInt(84)}
	bPoly := NewFromBig(bValues)

	result := aPoly.DeepCopy()
	err := result.mulFFT(bPoly)
	assert.Nil(t, err)
	assert.NotNil(t, result)

	// Expected result: 1008x^8 + 2100x^7 + 336x^6 + 540x^5 + 2553x^4 + 180x^3 + 765x
	expectedValues := []*big.Int{big.NewInt(0), big.NewInt(765), big.NewInt(0), big.NewInt(180), big.NewInt(2553), big.NewInt(540), big.NewInt(336), big.NewInt(2100), big.NewInt(1008)}
	expected := NewFromBig(expectedValues)

	assert.Equal(t, len(expected.Coefficients), len(result.Coefficients))
	assert.True(t, expected.Equal(result))
}

func TestMulPolyFFTEqual(t *testing.T) {
	n := 512
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)

	slice2 := randomFrSlice(n)
	poly2 := NewFromFr(slice2)

	result1 := poly1.DeepCopy()
	err := result1.mulNaive(poly2)
	assert.Nil(t, err)

	result2 := poly1.DeepCopy()
	err = result2.mulFFT(poly2)
	assert.Nil(t, err)

	assert.True(t, result1.Equal(result2))
}

func TestMulPolySparseEqual(t *testing.T) {
	sparseT := 16
	maxExp := big.NewInt(127)

	coefficientsA := randomFrSlice(sparseT)
	exponentsA := randomBigIntSlice(sparseT, maxExp)
	exponentsA[sparseT-1].Set(big.NewInt(128))
	polyA, err := NewSparse(coefficientsA, exponentsA)
	assert.Nil(t, err)

	coefficientsB := randomFrSlice(sparseT)
	exponentsB := randomBigIntSlice(sparseT, maxExp)
	exponentsB[sparseT-1].Set(big.NewInt(244)) // Check for different degree
	polyB, err := NewSparse(coefficientsB, exponentsB)
	assert.Nil(t, err)

	acopy1 := polyA.DeepCopy()
	err = acopy1.mulNaive(polyB)
	assert.Nil(t, err)

	acopy2 := polyA.DeepCopy()
	err = acopy2.mulFFT(polyB)
	assert.Nil(t, err)

	assert.True(t, acopy1.Equal(acopy2))
}

func TestNewRandomPolynomial(t *testing.T) {
	l := 1024
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	poly, err := NewRandomPolynomial(rng, l)
	assert.Nil(t, err)
	assert.NotNil(t, poly)
	deg, err := poly.Degree()
	assert.Nil(t, err)
	assert.Equal(t, l-1, deg)
	poly2, err := NewRandomPolynomial(rng, l)
	assert.Nil(t, err)
	assert.NotNil(t, poly2)
	assert.False(t, poly.Equal(poly2))
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

	poly.MulByConstant(constant)
	assert.True(t, expectedPoly.Equal(poly))
}

func TestMod(t *testing.T) {
	// Test polynomial a: 2x^2 + 2x + 1
	aValues := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(2)}
	aPoly := NewFromBig(aValues)
	// Test polynomial b: x^2
	bValues := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(1)}
	bPoly := NewFromBig(bValues)

	remainder, err := aPoly.modNaive(bPoly)
	assert.Nil(t, err)

	// Expected polynomial: 2x + 1
	expectedValues := []*big.Int{big.NewInt(1), big.NewInt(2)}
	expectedPoly := NewFromBig(expectedValues)

	assert.True(t, expectedPoly.Equal(remainder))
}

func TestModLarge(t *testing.T) {
	maxDegreeA := 512
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	aPoly, err := NewRandomPolynomial(rng, maxDegreeA)
	assert.Nil(t, err)
	maxDegreeB := 64
	bPoly, err := NewRandomPolynomial(rng, maxDegreeB)
	assert.Nil(t, err)

	remainder, err := aPoly.modNaive(bPoly)
	assert.Nil(t, err)

	deg, err := remainder.Degree()
	assert.Nil(t, err)
	degB, err := bPoly.Degree()
	assert.Nil(t, err)

	assert.True(t, deg < degB)
}

func BenchmarkMulNaiveN10(b *testing.B) { benchmarkMulNaive(b, 1024) }
func BenchmarkMulNaiveN11(b *testing.B) { benchmarkMulNaive(b, 2048) }
func BenchmarkMulNaiveN12(b *testing.B) { benchmarkMulNaive(b, 4096) }
func BenchmarkMulNaiveN13(b *testing.B) { benchmarkMulNaive(b, 8192) }
func BenchmarkMulNaiveN14(b *testing.B) { benchmarkMulNaive(b, 16384) }
func BenchmarkMulNaiveN15(b *testing.B) { benchmarkMulNaive(b, 32768) }
func BenchmarkMulNaiveN16(b *testing.B) { benchmarkMulNaive(b, 65536) }
func BenchmarkMulNaiveN17(b *testing.B) { benchmarkMulNaive(b, 131072) }
func BenchmarkMulNaiveN18(b *testing.B) { benchmarkMulNaive(b, 262144) }
func BenchmarkMulNaiveN19(b *testing.B) { benchmarkMulNaive(b, 524288) }
func BenchmarkMulNaiveN20(b *testing.B) { benchmarkMulNaive(b, 1048576) }

func BenchmarkMulFFTN10(b *testing.B) { benchmarkMulFFT(b, 1024) }
func BenchmarkMulFFTN11(b *testing.B) { benchmarkMulFFT(b, 2048) }
func BenchmarkMulFFTN12(b *testing.B) { benchmarkMulFFT(b, 4096) }
func BenchmarkMulFFTN13(b *testing.B) { benchmarkMulFFT(b, 8192) }
func BenchmarkMulFFTN14(b *testing.B) { benchmarkMulFFT(b, 16384) }
func BenchmarkMulFFTN15(b *testing.B) { benchmarkMulFFT(b, 32768) }
func BenchmarkMulFFTN16(b *testing.B) { benchmarkMulFFT(b, 65536) }
func BenchmarkMulFFTN17(b *testing.B) { benchmarkMulFFT(b, 131072) }
func BenchmarkMulFFTN18(b *testing.B) { benchmarkMulFFT(b, 262144) }
func BenchmarkMulFFTN19(b *testing.B) { benchmarkMulFFT(b, 524288) }
func BenchmarkMulFFTN20(b *testing.B) { benchmarkMulFFT(b, 1048576) }

func BenchmarkEvaluateNaiveN10(b *testing.B) { benchmarkEvaluationNaive(b, 1024) }
func BenchmarkEvaluateNaiveN11(b *testing.B) { benchmarkEvaluationNaive(b, 2048) }
func BenchmarkEvaluateNaiveN12(b *testing.B) { benchmarkEvaluationNaive(b, 4096) }
func BenchmarkEvaluateNaiveN13(b *testing.B) { benchmarkEvaluationNaive(b, 8192) }
func BenchmarkEvaluateNaiveN14(b *testing.B) { benchmarkEvaluationNaive(b, 16384) }
func BenchmarkEvaluateNaiveN15(b *testing.B) { benchmarkEvaluationNaive(b, 32768) }
func BenchmarkEvaluateNaiveN16(b *testing.B) { benchmarkEvaluationNaive(b, 65536) }
func BenchmarkEvaluateNaiveN17(b *testing.B) { benchmarkEvaluationNaive(b, 131072) }
func BenchmarkEvaluateNaiveN18(b *testing.B) { benchmarkEvaluationNaive(b, 262144) }
func BenchmarkEvaluateNaiveN19(b *testing.B) { benchmarkEvaluationNaive(b, 524288) }
func BenchmarkEvaluateNaiveN20(b *testing.B) { benchmarkEvaluationNaive(b, 1048576) }

func BenchmarkEvaluateHornerSeqN10(b *testing.B) { benchmarkEvaluationHornerSeq(b, 1024) }
func BenchmarkEvaluateHornerSeqN11(b *testing.B) { benchmarkEvaluationHornerSeq(b, 2048) }
func BenchmarkEvaluateHornerSeqN12(b *testing.B) { benchmarkEvaluationHornerSeq(b, 4096) }
func BenchmarkEvaluateHornerSeqN13(b *testing.B) { benchmarkEvaluationHornerSeq(b, 8192) }
func BenchmarkEvaluateHornerSeqN14(b *testing.B) { benchmarkEvaluationHornerSeq(b, 16384) }
func BenchmarkEvaluateHornerSeqN15(b *testing.B) { benchmarkEvaluationHornerSeq(b, 32768) }
func BenchmarkEvaluateHornerSeqN16(b *testing.B) { benchmarkEvaluationHornerSeq(b, 65536) }
func BenchmarkEvaluateHornerSeqN17(b *testing.B) { benchmarkEvaluationHornerSeq(b, 131072) }
func BenchmarkEvaluateHornerSeqN18(b *testing.B) { benchmarkEvaluationHornerSeq(b, 262144) }
func BenchmarkEvaluateHornerSeqN19(b *testing.B) { benchmarkEvaluationHornerSeq(b, 524288) }
func BenchmarkEvaluateHornerSeqN20(b *testing.B) { benchmarkEvaluationHornerSeq(b, 1048576) }

func BenchmarkEvaluateHornerParN10(b *testing.B) { benchmarkEvaluationHornerParallel(b, 1024) }
func BenchmarkEvaluateHornerParN11(b *testing.B) { benchmarkEvaluationHornerParallel(b, 2048) }
func BenchmarkEvaluateHornerParN12(b *testing.B) { benchmarkEvaluationHornerParallel(b, 4096) }
func BenchmarkEvaluateHornerParN13(b *testing.B) { benchmarkEvaluationHornerParallel(b, 8192) }
func BenchmarkEvaluateHornerParN14(b *testing.B) { benchmarkEvaluationHornerParallel(b, 16384) }
func BenchmarkEvaluateHornerParN15(b *testing.B) { benchmarkEvaluationHornerParallel(b, 32768) }
func BenchmarkEvaluateHornerParN16(b *testing.B) { benchmarkEvaluationHornerParallel(b, 65536) }
func BenchmarkEvaluateHornerParN17(b *testing.B) { benchmarkEvaluationHornerParallel(b, 131072) }
func BenchmarkEvaluateHornerParN18(b *testing.B) { benchmarkEvaluationHornerParallel(b, 262144) }
func BenchmarkEvaluateHornerParN19(b *testing.B) { benchmarkEvaluationHornerParallel(b, 524288) }
func BenchmarkEvaluateHornerParN20(b *testing.B) { benchmarkEvaluationHornerParallel(b, 1048576) }

func BenchmarkMulSparseNaiveD32768T16(t *testing.B)   { benchmarkMulSparseNaive(t, 32768, 16) }
func BenchmarkMulSparseNaiveD32768T128(t *testing.B)  { benchmarkMulSparseNaive(t, 32768, 128) }
func BenchmarkMulSparseNaiveD32768T256(t *testing.B)  { benchmarkMulSparseNaive(t, 32768, 256) }
func BenchmarkMulSparseNaiveD32768T384(t *testing.B)  { benchmarkMulSparseNaive(t, 32768, 384) }
func BenchmarkMulSparseNaiveD32768T512(t *testing.B)  { benchmarkMulSparseNaive(t, 32768, 512) }
func BenchmarkMulSparseNaiveD32768T768(t *testing.B)  { benchmarkMulSparseNaive(t, 32768, 768) }
func BenchmarkMulSparseNaiveD32768T1024(t *testing.B) { benchmarkMulSparseNaive(t, 32768, 1024) }
func BenchmarkMulSparseNaiveD32768T1536(t *testing.B) { benchmarkMulSparseNaive(t, 32768, 1536) }
func BenchmarkMulSparseNaiveD32768T2048(t *testing.B) { benchmarkMulSparseNaive(t, 32768, 2048) }
func BenchmarkMulSparseNaiveD32768T2560(t *testing.B) { benchmarkMulSparseNaive(t, 32768, 2560) }
func BenchmarkMulSparseNaiveD32768T3072(t *testing.B) { benchmarkMulSparseNaive(t, 32768, 3072) }

func BenchmarkMulSparseFFTD32768T16(t *testing.B)   { benchmarkMulSparseFFT(t, 32768, 16) }
func BenchmarkMulSparseFFTD32768T128(t *testing.B)  { benchmarkMulSparseFFT(t, 32768, 128) }
func BenchmarkMulSparseFFTD32768T256(t *testing.B)  { benchmarkMulSparseFFT(t, 32768, 256) }
func BenchmarkMulSparseFFTD32768T384(t *testing.B)  { benchmarkMulSparseFFT(t, 32768, 384) }
func BenchmarkMulSparseFFTD32768T512(t *testing.B)  { benchmarkMulSparseFFT(t, 32768, 512) }
func BenchmarkMulSparseFFTD32768T768(t *testing.B)  { benchmarkMulSparseFFT(t, 32768, 768) }
func BenchmarkMulSparseFFTD32768T1024(t *testing.B) { benchmarkMulSparseFFT(t, 32768, 1024) }
func BenchmarkMulSparseFFTD32768T1536(t *testing.B) { benchmarkMulSparseFFT(t, 32768, 1536) }
func BenchmarkMulSparseFFTD32768T2048(t *testing.B) { benchmarkMulSparseFFT(t, 32768, 2048) }
func BenchmarkMulSparseFFTD32768T2560(t *testing.B) { benchmarkMulSparseFFT(t, 32768, 2560) }
func BenchmarkMulSparseFFTD32768T3072(t *testing.B) { benchmarkMulSparseFFT(t, 32768, 3072) }

func BenchmarkMulSparseNaiveD262144T16(t *testing.B)   { benchmarkMulSparseNaive(t, 262144, 16) }
func BenchmarkMulSparseNaiveD262144T128(t *testing.B)  { benchmarkMulSparseNaive(t, 262144, 128) }
func BenchmarkMulSparseNaiveD262144T256(t *testing.B)  { benchmarkMulSparseNaive(t, 262144, 256) }
func BenchmarkMulSparseNaiveD262144T384(t *testing.B)  { benchmarkMulSparseNaive(t, 262144, 384) }
func BenchmarkMulSparseNaiveD262144T512(t *testing.B)  { benchmarkMulSparseNaive(t, 262144, 512) }
func BenchmarkMulSparseNaiveD262144T768(t *testing.B)  { benchmarkMulSparseNaive(t, 262144, 768) }
func BenchmarkMulSparseNaiveD262144T1024(t *testing.B) { benchmarkMulSparseNaive(t, 262144, 1024) }
func BenchmarkMulSparseNaiveD262144T1536(t *testing.B) { benchmarkMulSparseNaive(t, 262144, 1536) }
func BenchmarkMulSparseNaiveD262144T2048(t *testing.B) { benchmarkMulSparseNaive(t, 262144, 2048) }
func BenchmarkMulSparseNaiveD262144T3072(t *testing.B) { benchmarkMulSparseNaive(t, 262144, 3072) }
func BenchmarkMulSparseNaiveD262144T3584(t *testing.B) { benchmarkMulSparseNaive(t, 262144, 3584) }
func BenchmarkMulSparseNaiveD262144T4096(t *testing.B) { benchmarkMulSparseNaive(t, 262144, 4096) }
func BenchmarkMulSparseNaiveD262144T4609(t *testing.B) { benchmarkMulSparseNaive(t, 262144, 4609) }
func BenchmarkMulSparseNaiveD262144T5120(t *testing.B) { benchmarkMulSparseNaive(t, 262144, 5120) }

func BenchmarkMulSparseFFTD262144T16(t *testing.B)   { benchmarkMulSparseFFT(t, 262144, 16) }
func BenchmarkMulSparseFFTD262144T128(t *testing.B)  { benchmarkMulSparseFFT(t, 262144, 128) }
func BenchmarkMulSparseFFTD262144T256(t *testing.B)  { benchmarkMulSparseFFT(t, 262144, 256) }
func BenchmarkMulSparseFFTD262144T384(t *testing.B)  { benchmarkMulSparseFFT(t, 262144, 384) }
func BenchmarkMulSparseFFTD262144T512(t *testing.B)  { benchmarkMulSparseFFT(t, 262144, 512) }
func BenchmarkMulSparseFFTD262144T768(t *testing.B)  { benchmarkMulSparseFFT(t, 262144, 768) }
func BenchmarkMulSparseFFTD262144T1024(t *testing.B) { benchmarkMulSparseFFT(t, 262144, 1024) }
func BenchmarkMulSparseFFTD262144T1536(t *testing.B) { benchmarkMulSparseFFT(t, 262144, 1536) }
func BenchmarkMulSparseFFTD262144T2048(t *testing.B) { benchmarkMulSparseFFT(t, 262144, 2048) }
func BenchmarkMulSparseFFTD262144T3072(t *testing.B) { benchmarkMulSparseFFT(t, 262144, 3072) }
func BenchmarkMulSparseFFTD262144T3584(t *testing.B) { benchmarkMulSparseFFT(t, 262144, 3584) }
func BenchmarkMulSparseFFTD262144T4096(t *testing.B) { benchmarkMulSparseFFT(t, 262144, 4096) }
func BenchmarkMulSparseFFTD262144T4609(t *testing.B) { benchmarkMulSparseFFT(t, 262144, 4609) }
func BenchmarkMulSparseFFTD262144T5120(t *testing.B) { benchmarkMulSparseFFT(t, 262144, 5120) }

func benchmarkMulNaive(b *testing.B, n int) {
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)
	slice2 := randomFrSlice(n)
	poly2 := NewFromFr(slice2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		p := poly1.DeepCopy()
		b.StartTimer()
		_ = p.mulNaive(poly2)
	}
}

func benchmarkMulFFT(b *testing.B, n int) {
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)
	slice2 := randomFrSlice(n)
	poly2 := NewFromFr(slice2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		p := poly1.DeepCopy()
		b.StartTimer()
		err := p.mulFFT(poly2)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkMulSparseNaive(b *testing.B, degree, sparseness int) {
	poly1 := randomSparsePoly(sparseness, degree)
	poly2 := randomSparsePoly(sparseness, degree)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		p := poly1.DeepCopy()
		b.StartTimer()
		_ = p.mulNaive(poly2)
	}
}

func benchmarkMulSparseFFT(b *testing.B, degree, sparseness int) {
	poly1 := randomSparsePoly(sparseness, degree)
	poly2 := randomSparsePoly(sparseness, degree)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		p := poly1.DeepCopy()
		b.StartTimer()
		err := p.mulFFT(poly2)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkEvaluationHornerParallel(b *testing.B, n int) {
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)

	rng := rand.New(rand.NewSource(rand.Int63()))
	point, err := bls12381.NewFr().Rand(rng)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poly1.Evaluate(point)
	}
}

func benchmarkEvaluationHornerSeq(b *testing.B, n int) {
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)

	rng := rand.New(rand.NewSource(rand.Int63()))
	point, err := bls12381.NewFr().Rand(rng)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poly1.evaluateSequential(point)
	}
}

func benchmarkEvaluationNaive(b *testing.B, n int) {
	slice1 := randomFrSlice(n)
	poly1 := NewFromFr(slice1)

	rng := rand.New(rand.NewSource(rand.Int63()))
	point, err := bls12381.NewFr().Rand(rng)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poly1.evaluateNaive(point)
	}
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

func randomSparsePoly(sparseness, maxDegree int) *Polynomial {
	coefficients := randomFrSlice(sparseness)

	maxDegreeBigMinusOne := big.NewInt(int64(maxDegree - 1))
	exponents := randomBigIntSlice(sparseness-1, maxDegreeBigMinusOne)

	exponents = append(exponents, big.NewInt(int64(maxDegree)))

	poly, _ := NewSparse(coefficients, exponents)
	return poly
}
