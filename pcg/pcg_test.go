package pcg

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestPCGCombinedEnd2End(t *testing.T) {
	pcg, err := NewPCG(128, 10, 2, 2, 2, 4)
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

	eval0, err := pcg.EvalCombined(seeds[0], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval0)

	eval1, err := pcg.EvalCombined(seeds[1], randPolys, ring.Div)
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

func TestPCGSeparateEnd2End(t *testing.T) {
	pcg, err := NewPCG(128, 10, 3, 2, 2, 4) // n = 3
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

	signerSet := []int{0, 2} // Assume 2-of-3 with signer 0 and 2

	eval0, err := pcg.EvalSeparate(seeds[signerSet[0]], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval0)

	eval1, err := pcg.EvalSeparate(seeds[signerSet[1]], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval1)

	root := ring.Roots[10]
	tuple0 := eval0.GenBBSPlusTuple(root, signerSet)
	assert.NotNil(t, tuple0)
	tuple1 := eval1.GenBBSPlusTuple(root, signerSet)
	assert.NotNil(t, tuple1)

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

func Benchmark_2_Out_Of_2(b *testing.B) {
	benchmarkOpEvalCombined(b, 10, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 11, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 12, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 13, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 14, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 15, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 16, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 17, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 18, 2, 2, 4, 16)
}

func Benchmark_2_Out_Of_2_large(b *testing.B) {
	benchmarkOpEvalCombined(b, 19, 2, 2, 4, 16)
	benchmarkOpEvalCombined(b, 20, 2, 2, 4, 16)
}

func Benchmark_3_Out_Of3(b *testing.B) {
	benchmarkOpEvalCombined(b, 10, 3, 3, 4, 16)
	benchmarkOpEvalCombined(b, 11, 3, 3, 4, 16)
	benchmarkOpEvalCombined(b, 12, 3, 3, 4, 16)
	benchmarkOpEvalCombined(b, 13, 3, 3, 4, 16)
	benchmarkOpEvalCombined(b, 14, 3, 3, 4, 16)
	benchmarkOpEvalCombined(b, 15, 3, 3, 4, 16)
	benchmarkOpEvalCombined(b, 16, 3, 3, 4, 16)
	benchmarkOpEvalCombined(b, 17, 3, 3, 4, 16)
	benchmarkOpEvalCombined(b, 18, 3, 3, 4, 16)
}

func Benchmark_2_Out_Of_3(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 3, 4, 16)
	benchmarkOpEvalSeparate(b, 11, 2, 3, 4, 16)
	benchmarkOpEvalSeparate(b, 12, 2, 3, 4, 16)
	benchmarkOpEvalSeparate(b, 13, 2, 3, 4, 16)
	benchmarkOpEvalSeparate(b, 14, 2, 3, 4, 16)
	benchmarkOpEvalSeparate(b, 15, 2, 3, 4, 16)
	benchmarkOpEvalSeparate(b, 16, 2, 3, 4, 16)
}

// Benchmarking TrustedSeedGen
func BenchmarkTrustedSeedGenN20n2(b *testing.B) { benchmarkOpTrustedSeedGen(b, 20, 2, 4, 16) }
func BenchmarkTrustedSeedGenN20n3(b *testing.B) { benchmarkOpTrustedSeedGen(b, 20, 3, 4, 16) }

func benchmarkOpTrustedSeedGen(b *testing.B, N, n, c, t int) {
	pcg, err := NewPCG(128, N, n, 2, c, t)
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

func benchmarkOpEvalCombined(b *testing.B, N, tau, n, c, t int) {
	log.Printf("------------------- BENCHMARK EVAL COMBINED (n-out-of-n PCG) --------------------")
	log.Printf("N: %d, tau: %d, n: %d, c: %d, t: %d\n", N, tau, n, c, t)
	pcg, err := NewPCG(128, N, n, 2, c, t)
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
		_, err = pcg.EvalCombined(seeds[0], randPolys, ring.Div)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOpEvalSeparate(b *testing.B, N, tau, n, c, t int) {
	log.Printf("------------------- BENCHMARK EVAL SEPARATE (tau-out-of-n PCG) --------------------")
	log.Printf("N: %d, tau: %d, n: %d, c: %d, t: %d\n", N, tau, n, c, t)
	pcg, err := NewPCG(128, N, n, tau, c, t)
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
		_, err = pcg.EvalSeparate(seeds[0], randPolys, ring.Div)
		if err != nil {
			b.Fatal(err)
		}
	}
}
