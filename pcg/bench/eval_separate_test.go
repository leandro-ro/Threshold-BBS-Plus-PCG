package bench

import (
	"log"
	"pcg-bbs-plus/pcg"
	"testing"
)

// 2-out-of-3 Eval:
func BenchmarkOpEvalSeparate2outof3_N10(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N11(b *testing.B) {
	benchmarkOpEvalSeparate(b, 11, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N12(b *testing.B) {
	benchmarkOpEvalSeparate(b, 12, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N13(b *testing.B) {
	benchmarkOpEvalSeparate(b, 13, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N14(b *testing.B) {
	benchmarkOpEvalSeparate(b, 14, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N15(b *testing.B) {
	benchmarkOpEvalSeparate(b, 15, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N16(b *testing.B) {
	benchmarkOpEvalSeparate(b, 16, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N17(b *testing.B) {
	benchmarkOpEvalSeparate(b, 17, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N18(b *testing.B) {
	benchmarkOpEvalSeparate(b, 18, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N19(b *testing.B) {
	benchmarkOpEvalSeparate(b, 19, 2, 3, 4, 16)
}
func BenchmarkOpEvalSeparate2outof3_N20(b *testing.B) {
	benchmarkOpEvalSeparate(b, 20, 2, 3, 4, 16)
}

// 2-out-of-4 Eval:
func BenchmarkOpEvalSeparate2outof4_N10(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 4, 4, 16)
}
func BenchmarkOpEvalSeparate2outof4_N11(b *testing.B) {
	benchmarkOpEvalSeparate(b, 11, 2, 4, 4, 16)
}
func BenchmarkOpEvalSeparate2outof4_N12(b *testing.B) {
	benchmarkOpEvalSeparate(b, 12, 2, 4, 4, 16)
}
func BenchmarkOpEvalSeparate2outof4_N13(b *testing.B) {
	benchmarkOpEvalSeparate(b, 13, 2, 4, 4, 16)
}
func BenchmarkOpEvalSeparate2outof4_N14(b *testing.B) {
	benchmarkOpEvalSeparate(b, 14, 2, 4, 4, 16)
}
func BenchmarkOpEvalSeparate2outof4_N15(b *testing.B) {
	benchmarkOpEvalSeparate(b, 15, 2, 4, 4, 16)
}
func BenchmarkOpEvalSeparate2outof4_N16(b *testing.B) {
	benchmarkOpEvalSeparate(b, 16, 2, 4, 4, 16)
}
func BenchmarkOpEvalSeparate2outof4_N17(b *testing.B) {
	benchmarkOpEvalSeparate(b, 17, 2, 4, 4, 16)
}

// 2-out-of-5 Eval:
func BenchmarkOpEvalSeparate2outof5_N10(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 5, 4, 16)
}
func BenchmarkOpEvalSeparate2outof5_N11(b *testing.B) {
	benchmarkOpEvalSeparate(b, 11, 2, 5, 4, 16)
}
func BenchmarkOpEvalSeparate2outof5_N12(b *testing.B) {
	benchmarkOpEvalSeparate(b, 12, 2, 5, 4, 16)
}
func BenchmarkOpEvalSeparate2outof5_N13(b *testing.B) {
	benchmarkOpEvalSeparate(b, 13, 2, 5, 4, 16)
}
func BenchmarkOpEvalSeparate2outof5_N14(b *testing.B) {
	benchmarkOpEvalSeparate(b, 14, 2, 5, 4, 16)
}
func BenchmarkOpEvalSeparate2outof5_N15(b *testing.B) {
	benchmarkOpEvalSeparate(b, 15, 2, 5, 4, 16)
}
func BenchmarkOpEvalSeparate2outof5_N16(b *testing.B) {
	benchmarkOpEvalSeparate(b, 16, 2, 5, 4, 16)
}
func BenchmarkOpEvalSeparate2outof5_N17(b *testing.B) {
	benchmarkOpEvalSeparate(b, 17, 2, 5, 4, 16)
}

func BenchmarkOpEvalSeparate2outof6_N10(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 6, 4, 16)
}
func BenchmarkOpEvalSeparate2outof6_N11(b *testing.B) {
	benchmarkOpEvalSeparate(b, 11, 2, 6, 4, 16)
}
func BenchmarkOpEvalSeparate2outof6_N12(b *testing.B) {
	benchmarkOpEvalSeparate(b, 12, 2, 6, 4, 16)
}
func BenchmarkOpEvalSeparate2outof6_N13(b *testing.B) {
	benchmarkOpEvalSeparate(b, 13, 2, 6, 4, 16)
}
func BenchmarkOpEvalSeparate2outof6_N14(b *testing.B) {
	benchmarkOpEvalSeparate(b, 14, 2, 6, 4, 16)
}
func BenchmarkOpEvalSeparate2outof6_N15(b *testing.B) {
	benchmarkOpEvalSeparate(b, 15, 2, 6, 4, 16)
}
func BenchmarkOpEvalSeparate2outof6_N16(b *testing.B) {
	benchmarkOpEvalSeparate(b, 16, 2, 6, 4, 16)
}
func BenchmarkOpEvalSeparate2outof6_N17(b *testing.B) {
	benchmarkOpEvalSeparate(b, 17, 2, 6, 4, 16)
}

func BenchmarkOpEvalSeparate2outof7_N10(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 7, 4, 16)
}
func BenchmarkOpEvalSeparate2outof7_N11(b *testing.B) {
	benchmarkOpEvalSeparate(b, 11, 2, 7, 4, 16)
}
func BenchmarkOpEvalSeparate2outof7_N12(b *testing.B) {
	benchmarkOpEvalSeparate(b, 12, 2, 7, 4, 16)
}
func BenchmarkOpEvalSeparate2outof7_N13(b *testing.B) {
	benchmarkOpEvalSeparate(b, 13, 2, 7, 4, 16)
}
func BenchmarkOpEvalSeparate2outof7_N14(b *testing.B) {
	benchmarkOpEvalSeparate(b, 14, 2, 7, 4, 16)
}
func BenchmarkOpEvalSeparate2outof7_N15(b *testing.B) {
	benchmarkOpEvalSeparate(b, 15, 2, 7, 4, 16)
}
func BenchmarkOpEvalSeparate2outof7_N16(b *testing.B) {
	benchmarkOpEvalSeparate(b, 16, 2, 7, 4, 16)
}
func BenchmarkOpEvalSeparate2outof7_N17(b *testing.B) {
	benchmarkOpEvalSeparate(b, 17, 2, 7, 4, 16)
}

func BenchmarkOpEvalSeparate2outof8_N10(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 8, 4, 16)
}
func BenchmarkOpEvalSeparate2outof8_N11(b *testing.B) {
	benchmarkOpEvalSeparate(b, 11, 2, 8, 4, 16)
}
func BenchmarkOpEvalSeparate2outof8_N12(b *testing.B) {
	benchmarkOpEvalSeparate(b, 12, 2, 8, 4, 16)
}
func BenchmarkOpEvalSeparate2outof8_N13(b *testing.B) {
	benchmarkOpEvalSeparate(b, 13, 2, 8, 4, 16)
}
func BenchmarkOpEvalSeparate2outof8_N14(b *testing.B) {
	benchmarkOpEvalSeparate(b, 14, 2, 8, 4, 16)
}
func BenchmarkOpEvalSeparate2outof8_N15(b *testing.B) {
	benchmarkOpEvalSeparate(b, 15, 2, 8, 4, 16)
}
func BenchmarkOpEvalSeparate2outof8_N16(b *testing.B) {
	benchmarkOpEvalSeparate(b, 16, 2, 8, 4, 16)
}
func BenchmarkOpEvalSeparate2outof8_N17(b *testing.B) {
	benchmarkOpEvalSeparate(b, 17, 2, 8, 4, 16)
}

func BenchmarkOpEvalSeparate2outof9_N10(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 9, 4, 16)
}
func BenchmarkOpEvalSeparate2outof9_N11(b *testing.B) {
	benchmarkOpEvalSeparate(b, 11, 2, 9, 4, 16)
}
func BenchmarkOpEvalSeparate2outof9_N12(b *testing.B) {
	benchmarkOpEvalSeparate(b, 12, 2, 9, 4, 16)
}
func BenchmarkOpEvalSeparate2outof9_N13(b *testing.B) {
	benchmarkOpEvalSeparate(b, 13, 2, 9, 4, 16)
}
func BenchmarkOpEvalSeparate2outof9_N14(b *testing.B) {
	benchmarkOpEvalSeparate(b, 14, 2, 9, 4, 16)
}
func BenchmarkOpEvalSeparate2outof9_N15(b *testing.B) {
	benchmarkOpEvalSeparate(b, 15, 2, 9, 4, 16)
}
func BenchmarkOpEvalSeparate2outof9_N16(b *testing.B) {
	benchmarkOpEvalSeparate(b, 16, 2, 9, 4, 16)
}
func BenchmarkOpEvalSeparate2outof9_N17(b *testing.B) {
	benchmarkOpEvalSeparate(b, 17, 2, 9, 4, 16)
}

func BenchmarkOpEvalSeparate2outof10_N10(b *testing.B) {
	benchmarkOpEvalSeparate(b, 10, 2, 10, 4, 16)
}
func BenchmarkOpEvalSeparate2outof10_N11(b *testing.B) {
	benchmarkOpEvalSeparate(b, 11, 2, 10, 4, 16)
}
func BenchmarkOpEvalSeparate2outof10_N12(b *testing.B) {
	benchmarkOpEvalSeparate(b, 12, 2, 10, 4, 16)
}
func BenchmarkOpEvalSeparate2outof10_N13(b *testing.B) {
	benchmarkOpEvalSeparate(b, 13, 2, 10, 4, 16)
}
func BenchmarkOpEvalSeparate2outof10_N14(b *testing.B) {
	benchmarkOpEvalSeparate(b, 14, 2, 10, 4, 16)
}
func BenchmarkOpEvalSeparate2outof10_N15(b *testing.B) {
	benchmarkOpEvalSeparate(b, 15, 2, 10, 4, 16)
}
func BenchmarkOpEvalSeparate2outof10_N16(b *testing.B) {
	benchmarkOpEvalSeparate(b, 16, 2, 10, 4, 16)
}
func BenchmarkOpEvalSeparate2outof10_N17(b *testing.B) {
	benchmarkOpEvalSeparate(b, 17, 2, 10, 4, 16)
}

func benchmarkOpEvalSeparate(b *testing.B, N, tau, n, c, t int) {
	log.Printf("------------------- BENCHMARK EVAL SEPARATE (tau-out-of-n PCG) --------------------")
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

	ring, err := pcg.GetRing(false)
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
