package bench

import (
	"log"
	"pcg-master-thesis/pcg"
	"testing"
)

// 2-out-of-2 Eval:
func BenchmarkOpEvalCombined2outof2_N10(b *testing.B) {
	benchmarkOpEvalCombined(b, 10, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N11(b *testing.B) {
	benchmarkOpEvalCombined(b, 11, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N12(b *testing.B) {
	benchmarkOpEvalCombined(b, 12, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N13(b *testing.B) {
	benchmarkOpEvalCombined(b, 13, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N14(b *testing.B) {
	benchmarkOpEvalCombined(b, 14, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N15(b *testing.B) {
	benchmarkOpEvalCombined(b, 15, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N16(b *testing.B) {
	benchmarkOpEvalCombined(b, 16, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N17(b *testing.B) {
	benchmarkOpEvalCombined(b, 17, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N18(b *testing.B) {
	benchmarkOpEvalCombined(b, 18, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N19(b *testing.B) {
	benchmarkOpEvalCombined(b, 19, 2, 2, 4, 16)
}
func BenchmarkOpEvalCombined2outof2_N20(b *testing.B) {
	benchmarkOpEvalCombined(b, 20, 2, 2, 4, 16)
}

// 3-out-of-3 Eval:
func BenchmarkOpEvalCombined3outof3_N10(b *testing.B) {
	benchmarkOpEvalCombined(b, 10, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N11(b *testing.B) {
	benchmarkOpEvalCombined(b, 11, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N12(b *testing.B) {
	benchmarkOpEvalCombined(b, 12, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N13(b *testing.B) {
	benchmarkOpEvalCombined(b, 13, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N14(b *testing.B) {
	benchmarkOpEvalCombined(b, 14, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N15(b *testing.B) {
	benchmarkOpEvalCombined(b, 15, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N16(b *testing.B) {
	benchmarkOpEvalCombined(b, 16, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N17(b *testing.B) {
	benchmarkOpEvalCombined(b, 17, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N18(b *testing.B) {
	benchmarkOpEvalCombined(b, 18, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N19(b *testing.B) {
	benchmarkOpEvalCombined(b, 19, 3, 3, 4, 16)
}
func BenchmarkOpEvalCombined3outof3_N20(b *testing.B) {
	benchmarkOpEvalCombined(b, 20, 3, 3, 4, 16)
}

// 4-out-of-4 Eval:
func BenchmarkOpEvalCombined4outof4_N10(b *testing.B) {
	benchmarkOpEvalCombined(b, 10, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N11(b *testing.B) {
	benchmarkOpEvalCombined(b, 11, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N12(b *testing.B) {
	benchmarkOpEvalCombined(b, 12, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N13(b *testing.B) {
	benchmarkOpEvalCombined(b, 13, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N14(b *testing.B) {
	benchmarkOpEvalCombined(b, 14, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N15(b *testing.B) {
	benchmarkOpEvalCombined(b, 15, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N16(b *testing.B) {
	benchmarkOpEvalCombined(b, 16, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N17(b *testing.B) {
	benchmarkOpEvalCombined(b, 17, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N18(b *testing.B) {
	benchmarkOpEvalCombined(b, 18, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N19(b *testing.B) {
	benchmarkOpEvalCombined(b, 19, 4, 4, 4, 16)
}
func BenchmarkOpEvalCombined4outof4_N20(b *testing.B) {
	benchmarkOpEvalCombined(b, 20, 4, 4, 4, 16)
}

func benchmarkOpEvalCombined(b *testing.B, N, tau, n, c, t int) {
	log.Printf("------------------- BENCHMARK EVAL COMBINED (n-out-of-n PCG) --------------------")
	log.Printf("N: %d, tau: %d, n: %d, c: %d, t: %d\n", N, tau, n, c, t)
	pcg, err := pcg.NewPCG(128, N, n, tau, c, t)
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
