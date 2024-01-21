package dspf

import (
	"crypto/rand"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"math/big"
	treedpf "pcg-master-thesis/dpf/2015_boyle_tree_based"
	optreedpf "pcg-master-thesis/dpf/2018_boyle_optimization"
	"testing"
)

func TestDSPFGenMismatchedLengths(t *testing.T) {
	var dspfInstance DSPF
	specialPoints := []*big.Int{big.NewInt(1)}
	nonZeroElements := []*big.Int{big.NewInt(2), big.NewInt(3)}

	_, _, err := dspfInstance.Gen(specialPoints, nonZeroElements)
	if err == nil || err.Error() != "the number of special points and non-zero elements must match" {
		t.Errorf("Gen did not return the correct error for mismatched lengths")
	}
}

// We allow duplicate special points for now
// func TestDSPFGenDuplicateSpecialPoints(t *testing.T) {
//	var dspfInstance DSPF
//	specialPoint := big.NewInt(1)
//	specialPoints := []*big.Int{specialPoint, specialPoint}
//	nonZeroElements := []*big.Int{big.NewInt(2), big.NewInt(3)}
//
//	_, _, err := dspfInstance.Gen(specialPoints, nonZeroElements)
//	if err == nil || err.Error() != fmt.Sprintf("duplicate special point: %s", specialPoint.Text(10)) {
//		t.Errorf("Gen did not return the correct error for duplicate special points")
//	}
// }

func TestDSPFGenEvalTreeDPF(t *testing.T) {
	treeDPF128, err := treedpf.InitFactory(128, 128)
	if err != nil {
		t.Errorf("InitFactory returned an unexpected error: %v", err)
	}
	dspf := NewDSPFFactory(treeDPF128)
	sp1 := big.NewInt(1)
	nz1 := big.NewInt(3)

	sp2 := big.NewInt(5)
	nz2 := big.NewInt(61)

	sp3 := big.NewInt(27)
	nz3 := big.NewInt(82)

	specialPoints := []*big.Int{sp1, sp2, sp3}
	nonZeroElements := []*big.Int{nz1, nz2, nz3}

	var keyAlice Key
	var keyBob Key
	keyAlice, keyBob, err = dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		t.Errorf("Gen returned an unexpected error for valid input: %v", err)
	}
	if keyAlice.DPFKeys == nil || keyBob.DPFKeys == nil {
		t.Errorf("Gen returned nil keys")
	}

	// Test EvalCombined
	x := big.NewInt(2)
	var ysAlice []*big.Int
	var ysBob []*big.Int
	ysAlice, err = dspf.Eval(keyAlice, x)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}
	ysBob, err = dspf.Eval(keyBob, x)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}

	// Test CombineSingleResult
	var result *big.Int
	result, err = dspf.CombineSingleResult(ysAlice, ysBob)
	if err != nil {
		t.Errorf("CombineSingleResult returned an unexpected error: %v", err)
	}
	// Expect result to be zero
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("CombineSingleResult did not return zero")
	}

	// Test EvalCombined with non-zero result
	x = sp2
	ysAlice, err = dspf.Eval(keyAlice, x)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}
	ysBob, err = dspf.Eval(keyBob, x)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}
	result, err = dspf.CombineSingleResult(ysAlice, ysBob)
	if err != nil {
		t.Errorf("CombineSingleResult returned an unexpected error: %v", err)
	}

	// Expect result to be non-zero
	if result.Cmp(nz2) != 0 {
		t.Errorf("CombineSingleResult did not return the correct result")
	}
}

func TestDSPFGenEvalOpTreeDPF(t *testing.T) {
	treedpf12864, err := optreedpf.InitFactory(128, 64)
	if err != nil {
		t.Errorf("InitFactory returned an unexpected error: %v", err)
	}
	dspf := NewDSPFFactory(treedpf12864)
	sp1 := big.NewInt(1)
	nz1 := big.NewInt(3)

	sp2 := big.NewInt(5)
	nz2 := big.NewInt(61)

	sp3 := big.NewInt(27)
	nz3 := big.NewInt(82)

	specialPoints := []*big.Int{sp1, sp2, sp3}
	nonZeroElements := []*big.Int{nz1, nz2, nz3}

	var keyAlice Key
	var keyBob Key
	keyAlice, keyBob, err = dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		t.Errorf("Gen returned an unexpected error for valid input: %v", err)
	}
	if keyAlice.DPFKeys == nil || keyBob.DPFKeys == nil {
		t.Errorf("Gen returned nil keys")
	}

	// Test EvalCombined
	x := big.NewInt(2)
	var ysAlice []*big.Int
	var ysBob []*big.Int
	ysAlice, err = dspf.Eval(keyAlice, x)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}
	ysBob, err = dspf.Eval(keyBob, x)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}

	// Test CombineSingleResult
	var result *big.Int
	result, err = dspf.CombineSingleResult(ysAlice, ysBob)
	if err != nil {
		t.Errorf("CombineSingleResult returned an unexpected error: %v", err)
	}
	// Expect result to be zero
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("CombineSingleResult did not return zero")
	}

	// Test EvalCombined with non-zero result
	x = sp2
	ysAlice, err = dspf.Eval(keyAlice, x)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}
	ysBob, err = dspf.Eval(keyBob, x)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}
	result, err = dspf.CombineSingleResult(ysAlice, ysBob)
	if err != nil {
		t.Errorf("CombineSingleResult returned an unexpected error: %v", err)
	}

	// Expect result to be non-zero
	if result.Cmp(nz2) != 0 {
		t.Errorf("CombineSingleResult did not return the correct result")
	}
}

func TestDSPFFullEvalOpTreeDPF(t *testing.T) {
	domain := 10
	treedpf128n10, err := optreedpf.InitFactory(128, domain) // Small domain size for testing
	if err != nil {
		t.Errorf("InitFactory returned an unexpected error: %v", err)
	}
	dspf := NewDSPFFactory(treedpf128n10)

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)

	tCount := 6 // Number of random points and elements to generate
	specialPoints := make([]*big.Int, tCount)
	nonZeroElements := make([]*big.Int, tCount)

	for i := 0; i < tCount; i++ {
		x, err := rand.Int(rand.Reader, maxInputX)
		if err != nil {
			t.Errorf("Error generating random x: %v", err)
		}
		specialPoints[i] = x

		y, err := rand.Int(rand.Reader, treedpf128n10.BetaMax) // Max input is the base field size
		if err != nil {
			t.Errorf("Error generating random y: %v", err)
		}
		nonZeroElements[i] = y
	}

	k1, k2, err := dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		return
	}

	ys1, err := dspf.FullEval(k1)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}

	ys2, err := dspf.FullEval(k2)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}

	for i := 0; i < tCount; i++ {
		res, err := dspf.CombineSingleResult(ys1[i], ys2[i])
		if err != nil {
			t.Errorf("CombineSingleResult returned an unexpected error: %v", err)
		}

		assert.Equal(t, 0, res.Cmp(nonZeroElements[i]))
	}

	resFull, err := dspf.CombineMultipleResults(ys1, ys2)
	assert.Nil(t, err)
	assert.Equal(t, len(resFull), len(ys1))
	for i := 0; i < len(resFull); i++ {
		assert.Equal(t, 0, resFull[i].Cmp(nonZeroElements[i]))
	}
}

func TestDSPFFullEvalFastOpTreeDPF(t *testing.T) {
	domain := 10
	treedpf128n10, err := optreedpf.InitFactory(128, domain) // Small domain size for testing
	if err != nil {
		t.Errorf("InitFactory returned an unexpected error: %v", err)
	}
	dspf := NewDSPFFactory(treedpf128n10)

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)

	tCount := 6 // Number of random points and elements to generate
	specialPoints := make([]*big.Int, tCount)
	nonZeroElements := make([]*big.Int, tCount)

	for i := 0; i < tCount; i++ {
		x, err := rand.Int(rand.Reader, maxInputX)
		if err != nil {
			t.Errorf("Error generating random x: %v", err)
		}
		specialPoints[i] = x

		y, err := rand.Int(rand.Reader, treedpf128n10.BetaMax) // Max input is the base field size
		if err != nil {
			t.Errorf("Error generating random y: %v", err)
		}
		nonZeroElements[i] = y
	}

	k1, k2, err := dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		return
	}

	ys1, err := dspf.FullEvalFast(k1)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}

	ys2, err := dspf.FullEvalFast(k2)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}

	for i := 0; i < tCount; i++ {
		res, err := dspf.CombineSingleResult(ys1[i], ys2[i])
		if err != nil {
			t.Errorf("CombineSingleResult returned an unexpected error: %v", err)
		}

		assert.Equal(t, 0, res.Cmp(nonZeroElements[i]))
	}

	resFull, err := dspf.CombineMultipleResults(ys1, ys2)
	assert.Nil(t, err)
	assert.Equal(t, len(resFull), len(ys1))
	for i := 0; i < len(resFull); i++ {
		assert.Equal(t, 0, resFull[i].Cmp(nonZeroElements[i]))
	}
}

func TestDSPFFullEvalFastOpTreeDPFSum(t *testing.T) {
	domain := 10
	treedpf128n10, err := optreedpf.InitFactory(128, domain) // Small domain size for testing
	if err != nil {
		t.Errorf("InitFactory returned an unexpected error: %v", err)
	}
	dspf := NewDSPFFactory(treedpf128n10)

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)

	tCount := 6 // Number of random points and elements to generate
	specialPoints := make([]*big.Int, tCount)
	nonZeroElements := make([]*big.Int, tCount)

	for i := 0; i < tCount; i++ {
		x, err := rand.Int(rand.Reader, maxInputX)
		if err != nil {
			t.Errorf("Error generating random x: %v", err)
		}
		specialPoints[i] = x

		y, err := rand.Int(rand.Reader, treedpf128n10.BetaMax) // Max input is the base field size
		if err != nil {
			t.Errorf("Error generating random y: %v", err)
		}
		nonZeroElements[i] = y
	}

	k1, k2, err := dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		return
	}

	ys1, err := dspf.FullEvalFast(k1)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}

	ys2, err := dspf.FullEvalFast(k2)
	if err != nil {
		t.Errorf("EvalCombined returned an unexpected error: %v", err)
	}

	ys1summed := make([]*bls12381.Fr, len(ys1[0]))
	for i := 0; i < len(ys1[0]); i++ {
		for j := 0; j < len(ys1); j++ {
			if ys1summed[i] == nil {
				ys1summed[i] = bls12381.NewFr()
			}
			val := bls12381.NewFr().FromBytes(ys1[j][i].Bytes())
			ys1summed[i].Add(ys1summed[i], val)
		}
	}

	ys2summed := make([]*bls12381.Fr, len(ys2[0]))
	for i := 0; i < len(ys2[0]); i++ {
		for j := 0; j < len(ys2); j++ {
			if ys2summed[i] == nil {
				ys2summed[i] = bls12381.NewFr()
			}
			val := bls12381.NewFr().FromBytes(ys2[j][i].Bytes())
			ys2summed[i].Add(ys2summed[i], val)
		}
	}

	result := make([]*bls12381.Fr, len(ys1summed))
	for i := 0; i < len(result); i++ {
		result[i] = bls12381.NewFr()
		result[i].Add(ys1summed[i], ys2summed[i])
	}

	for i := 0; i < len(result); i++ {
		found := false
		for pos, specialPoint := range specialPoints {
			if big.NewInt(int64(i)).Cmp(specialPoint) == 0 {
				val := result[i].ToBig()
				assert.Equal(t, 0, val.Cmp(nonZeroElements[pos]))
				found = true
			}
		}
		if !found {
			assert.Equal(t, 0, result[i].ToBig().Cmp(big.NewInt(0)))
		}
	}
}

// Benchmarks:
func BenchmarkOpTreeDSPFFullEval128_n10_t6(b *testing.B) { benchmarkOpTreeDSPFFullEval(b, 128, 10, 6) }
func BenchmarkOpTreeDSPFFullEval128_n15_t6(b *testing.B) { benchmarkOpTreeDSPFFullEval(b, 128, 15, 6) }

// The parameters chosen below are similar to the ones used in the PCG.
// t = 16:
func BenchmarkOpTreeDSPFFullEvalFast128_n10_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 10, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n11_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 11, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n12_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 12, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n13_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 13, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n14_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 14, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n15_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 15, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n16_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 16, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n17_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 17, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n18_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 18, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n19_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 19, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n20_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 20, 16)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n21_t16(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 21, 16)
}

// The parameters chosen below are similar to the ones used in the PCG.
// t = 16 -> t*t = 256:
func BenchmarkOpTreeDSPFFullEvalFast128_n10_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 10, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n11_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 11, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n12_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 12, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n13_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 13, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n14_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 14, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n15_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 15, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n16_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 16, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n17_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 17, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n18_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 18, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n19_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 19, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n20_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 20, 256)
}
func BenchmarkOpTreeDSPFFullEvalFast128_n21_t256(b *testing.B) {
	benchmarkOpTreeDSPFFullEvalFast(b, 128, 21, 256)
}

func benchmarkOpTreeDSPFFullEval(b *testing.B, lambda, domain, t int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	if err != nil {
		b.Fatal(err)
	}
	dspf := NewDSPFFactory(d)
	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)

	specialPoints := make([]*big.Int, t)
	nonZeroElements := make([]*big.Int, t)

	for i := 0; i < t; i++ {
		x, err := rand.Int(rand.Reader, maxInputX)
		if err != nil {
			b.Errorf("Error generating random x: %v", err)
		}
		specialPoints[i] = x

		y, err := rand.Int(rand.Reader, d.BetaMax) // Max input is the base field size
		if err != nil {
			b.Errorf("Error generating random y: %v", err)
		}
		nonZeroElements[i] = y
	}

	k1, _, err := dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dspf.FullEval(k1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOpTreeDSPFFullEvalFast(b *testing.B, lambda, domain, t int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	if err != nil {
		b.Fatal(err)
	}
	dspf := NewDSPFFactory(d)
	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)

	specialPoints := make([]*big.Int, t)
	nonZeroElements := make([]*big.Int, t)

	for i := 0; i < t; i++ {
		x, err := rand.Int(rand.Reader, maxInputX)
		if err != nil {
			b.Errorf("Error generating random x: %v", err)
		}
		specialPoints[i] = x

		y, err := rand.Int(rand.Reader, d.BetaMax) // Max input is the base field size
		if err != nil {
			b.Errorf("Error generating random y: %v", err)
		}
		nonZeroElements[i] = y
	}

	k1, _, err := dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dspf.FullEvalFast(k1)
		if err != nil {
			b.Fatal(err)
		}
	}
}
