package bench

import (
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"math/rand"
	"pcg-bbs-plus/pcg"
	"pcg-bbs-plus/pcg/poly"
	"testing"
)

func BenchmarkDeriveTuple_N10(b *testing.B) {
	benchmarkDeriveTuple(b, 10)
}
func BenchmarkDeriveTuple_N11(b *testing.B) {
	benchmarkDeriveTuple(b, 11)
}
func BenchmarkDeriveTuple_N12(b *testing.B) {
	benchmarkDeriveTuple(b, 12)
}
func BenchmarkDeriveTuple_N13(b *testing.B) {
	benchmarkDeriveTuple(b, 13)
}
func BenchmarkDeriveTuple_N14(b *testing.B) {
	benchmarkDeriveTuple(b, 14)
}
func BenchmarkDeriveTuple_N15(b *testing.B) {
	benchmarkDeriveTuple(b, 15)
}
func BenchmarkDeriveTuple_N16(b *testing.B) {
	benchmarkDeriveTuple(b, 16)
}
func BenchmarkDeriveTuple_N17(b *testing.B) {
	benchmarkDeriveTuple(b, 17)
}
func BenchmarkDeriveTuple_N18(b *testing.B) {
	benchmarkDeriveTuple(b, 18)
}
func BenchmarkDeriveTuple_N19(b *testing.B) {
	benchmarkDeriveTuple(b, 19)
}
func BenchmarkDeriveTuple_N20(b *testing.B) {
	benchmarkDeriveTuple(b, 20)
}

func benchmarkDeriveTuple(b *testing.B, N int) {
	c, t := 4, 16
	pcgenerator, err := pcg.NewPCG(128, N, 2, 2, c, t)
	if err != nil {
		b.Fatal(err)
	}

	ring, err := pcgenerator.GetRing(false)
	if err != nil {
		b.Fatal(err)
	}

	rng := rand.New(rand.NewSource(rand.Int63()))
	sk, _ := bls12381.NewFr().Rand(rng)

	pow2N := big.NewInt(0)
	pow2N.Exp(big.NewInt(2), big.NewInt(int64(N)), nil)

	// We can use random polynomials here, since we are only interested in the runtime of the tuple generation.
	alphaPoly := randomPoly(pow2N)
	delta1Poly := randomPoly(pow2N)
	delta0Poly := randomPoly(pow2N)
	aPoly := randomPoly(pow2N)
	ePoly := randomPoly(pow2N)
	sPoly := randomPoly(pow2N)

	tupleGenerator := pcg.NewBBSPlusTupleGenerator(sk, aPoly, ePoly, sPoly, alphaPoly, delta0Poly, delta1Poly)

	root := ring.Roots[10]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tupleGenerator.GenBBSPlusTuple(root)
	}
}

func randomPoly(n *big.Int) *poly.Polynomial {
	slice := make([]*bls12381.Fr, n.Int64())

	rng := rand.New(rand.NewSource(rand.Int63()))
	for i := range slice {
		randVal := bls12381.NewFr()
		slice[i] = bls12381.NewFr()
		fr, _ := randVal.Rand(rng)
		slice[i].Set(fr)
	}
	return poly.NewFromFr(slice)
}
