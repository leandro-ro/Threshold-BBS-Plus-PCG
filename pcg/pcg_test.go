package pcg

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestPCGEnd2End(t *testing.T) {
	pcg, err := NewPCG(128, 10, 2, 4, 16)
	assert.Nil(t, err)

	seeds, err := pcg.TrustedSeedGen()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	ring, err := pcg.GetRing(true)
	assert.Nil(t, err)
	assert.NotNil(t, ring)

	eval0, err := pcg.Eval(seeds[0], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval0)

	eval1, err := pcg.Eval(seeds[1], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval1)

	keyNr := 10
	root := ring.Roots[keyNr]

	tuple0 := eval0.GenBBSPlusTuple(root)
	tuple1 := eval1.GenBBSPlusTuple(root)

	sk := bls12381.NewFr()
	sk.Add(tuple0.SkShare, tuple1.SkShare)

	seedSk := bls12381.NewFr()
	seedSk.Add(seeds[0].ski, seeds[1].ski)
	assert.Equal(t, 0, sk.Cmp(seedSk))

	a := bls12381.NewFr() // Sum up a0 and a1
	a.Add(tuple0.AShare, tuple1.AShare)

	s := bls12381.NewFr() // Sum up s0 and s1
	s.Add(tuple0.SShare, tuple1.SShare)

	e := bls12381.NewFr() // Sum up e0 and e1
	e.Add(tuple0.EShare, tuple1.EShare)

	alpha := bls12381.NewFr()
	alpha.Add(tuple0.AlphaShare, tuple1.AlphaShare)

	delta := bls12381.NewFr()
	delta.Add(tuple0.DeltaShare, tuple1.DeltaShare)

	ask := bls12381.NewFr() // = delta0
	ask.Mul(a, sk)

	ae := bls12381.NewFr() // = delta1
	ae.Mul(a, e)

	// Check if correlations hold
	askPae := bls12381.NewFr() // = a(sk + e)
	askPae.Add(ask, ae)
	assert.Equal(t, 0, delta.Cmp(askPae))

	as := bls12381.NewFr()
	as.Mul(a, s)
	assert.Equal(t, 0, alpha.Cmp(as))
}

func BenchmarkOvernight(b *testing.B) {
	BenchmarkEvalN12(b)
	BenchmarkEvalN13(b)
	BenchmarkEvalN14(b)
}

// Benchmarking TrustedSeedGen
func BenchmarkTrustedSeedGenN20n2(b *testing.B) { benchmarkOpTrustedSeedGen(b, 20, 2, 4, 16) } // 0.8367157s
func BenchmarkTrustedSeedGenN20n3(b *testing.B) { benchmarkOpTrustedSeedGen(b, 20, 3, 4, 16) } // 2.407096s

// Benchmarking Eval
func BenchmarkEvalN7(b *testing.B)  { benchmarkOpEval(b, 7, 2, 4, 16) }
func BenchmarkEvalN8(b *testing.B)  { benchmarkOpEval(b, 8, 2, 4, 16) }
func BenchmarkEvalN9(b *testing.B)  { benchmarkOpEval(b, 9, 2, 4, 16) }  // 34.27199s (0.0668s per sig)
func BenchmarkEvalN10(b *testing.B) { benchmarkOpEval(b, 10, 2, 4, 16) } // 104.4729s (0.1020s per sig)
func BenchmarkEvalN11(b *testing.B) { benchmarkOpEval(b, 11, 2, 4, 16) } // 170.8978s (0.0834s per sig)
func BenchmarkEvalN12(b *testing.B) { benchmarkOpEval(b, 12, 2, 4, 16) } // 336.8978s (0.0822s per sig)
func BenchmarkEvalN13(b *testing.B) { benchmarkOpEval(b, 13, 2, 4, 16) }
func BenchmarkEvalN14(b *testing.B) { benchmarkOpEval(b, 14, 2, 4, 16) }
func BenchmarkEvalN15(b *testing.B) { benchmarkOpEval(b, 15, 2, 4, 16) }
func BenchmarkEvalN16(b *testing.B) { benchmarkOpEval(b, 16, 2, 4, 16) }
func BenchmarkEvalN17(b *testing.B) { benchmarkOpEval(b, 17, 2, 4, 16) }
func BenchmarkEvalN18(b *testing.B) { benchmarkOpEval(b, 18, 2, 4, 16) }
func BenchmarkEvalN19(b *testing.B) { benchmarkOpEval(b, 19, 2, 4, 16) }
func BenchmarkEvalN20(b *testing.B) { benchmarkOpEval(b, 20, 2, 4, 16) }

func benchmarkOpTrustedSeedGen(b *testing.B, N, n, c, t int) {
	pcg, err := NewPCG(128, N, n, c, t)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = pcg.TrustedSeedGen()
		if err != nil {
			b.Fatal(err)
		}
	}

}

func benchmarkOpEval(b *testing.B, N, n, c, t int) {
	log.Printf("------------------- BENCHMARK EVAL --------------------")
	log.Printf("N: %d, n: %d, c: %d, t: %d\n", N, n, c, t)
	pcg, err := NewPCG(128, N, n, c, t)
	if err != nil {
		b.Fatal(err)
	}

	seeds, err := pcg.TrustedSeedGen()
	if err != nil {
		b.Fatal(err)
	}

	randPolys, err := pcg.PickRandomPolynomials()
	if err != nil {
		b.Fatal(err)
	}

	ring, err := pcg.GetRing(true)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = pcg.Eval(seeds[0], randPolys, ring.Div)
		if err != nil {
			b.Fatal(err)
		}
	}
}
