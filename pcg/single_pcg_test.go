package pcg

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestSingleOLE(t *testing.T) {
	pcg, err := NewPCG(128, 10, 2, 2, 2, 4) // Small lpn parameters for testing.
	assert.Nil(t, err)

	seeds, err := pcg.genSingleOlePCG()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	ring, err := pcg.GetRing(false)
	assert.Nil(t, err)
	assert.NotNil(t, ring)

	x0, z0, err := pcg.evalSingleOle(seeds[0], randPolys, ring.Div)
	x1, z1, err := pcg.evalSingleOle(seeds[1], randPolys, ring.Div)

	assert.Nil(t, err)
	assert.NotNil(t, x0)
	assert.NotNil(t, z0)
	assert.NotNil(t, x1)
	assert.NotNil(t, z1)

	// Check if the polynomials are correct
	root := ring.Roots[57]

	x0Eval := x0.Evaluate(root)
	x1Eval := x1.Evaluate(root)
	z0Eval := z0.Evaluate(root)
	z1Eval := z1.Evaluate(root)
	assert.NotNil(t, x0Eval)
	assert.NotNil(t, x1Eval)
	assert.NotNil(t, z0Eval)
	assert.NotNil(t, z1Eval)

	// Check if the OLE correlation holds
	x := bls12381.NewFr().Zero()
	x.Mul(x0Eval, x1Eval)

	y := bls12381.NewFr().Zero()
	y.Add(z0Eval, z1Eval)

	assert.Equal(t, 0, x.Cmp(y))
}

func TestSingleVOLE(t *testing.T) {
	pcg, err := NewPCG(128, 10, 2, 2, 2, 4) // Small lpn parameters for testing.
	assert.Nil(t, err)

	seeds, err := pcg.genSingleVolePCG()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	ring, err := pcg.GetRing(false)
	assert.Nil(t, err)
	assert.NotNil(t, ring)

	x0, z0, err := pcg.evalSingleVole(seeds[0], randPolys, ring.Div)
	x1, z1, err := pcg.evalSingleVole(seeds[1], randPolys, ring.Div) // x1 contains constant

	assert.Nil(t, err)
	assert.NotNil(t, x0)
	assert.NotNil(t, z0)
	assert.NotNil(t, x1)
	assert.NotNil(t, z1)

	// Check if the polynomials are correct
	root := ring.Roots[57]

	x0Eval := x0.Evaluate(root)
	x1Eval := x1.Evaluate(root)
	z0Eval := z0.Evaluate(root)
	z1Eval := z1.Evaluate(root)
	assert.NotNil(t, x0Eval)
	assert.NotNil(t, x1Eval)
	assert.NotNil(t, z0Eval)
	assert.NotNil(t, z1Eval)

	// Check if the OLE correlation holds
	x := bls12381.NewFr().Zero()
	x.Mul(x0Eval, x1Eval)

	y := bls12381.NewFr().Zero()
	y.Add(z0Eval, z1Eval)

	assert.Equal(t, 0, x.Cmp(y))
}

// Benchmarks for single OLE and VOLE PCG generation and evaluation.
func BenchmarkSingleOLEPCGGenerationN10(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 10, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN11(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 11, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN12(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 12, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN13(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 13, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN14(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 14, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN15(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 15, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN16(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 16, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN17(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 17, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN18(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 18, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN19(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 19, 4, 16) }
func BenchmarkSingleOLEPCGGenerationN20(b *testing.B) { benchmarkSingleOLEpcgGeneration(b, 20, 4, 16) }

func BenchmarkSingleOLEPCGEvaluationN10(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 10, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN11(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 11, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN12(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 12, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN13(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 13, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN14(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 14, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN15(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 15, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN16(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 16, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN17(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 17, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN18(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 18, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN19(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 19, 4, 16) }
func BenchmarkSingleOLEPCGEvaluationN20(b *testing.B) { benchmarkSingleOLEpcgEvaluation(b, 20, 4, 16) }

func BenchmarkSingleVOLEPCGGenerationN10(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 10, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN11(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 11, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN12(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 12, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN13(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 13, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN14(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 14, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN15(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 15, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN16(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 16, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN17(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 17, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN18(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 18, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN19(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 19, 4, 16)
}
func BenchmarkSingleVOLEPCGGenerationN20(b *testing.B) {
	benchmarkSingleVOLEpcgGeneration(b, 20, 4, 16)
}

func BenchmarkSingleVOLEPCGEvaluationN10(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 10, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN11(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 11, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN12(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 12, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN13(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 13, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN14(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 14, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN15(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 15, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN16(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 16, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN17(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 17, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN18(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 18, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN19(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 19, 4, 16)
}
func BenchmarkSingleVOLEPCGEvaluationN20(b *testing.B) {
	benchmarkSingleVOLEpcgEvaluation(b, 20, 4, 16)
}

func benchmarkSingleOLEpcgGeneration(b *testing.B, N, c, t int) {
	pcg, err := NewPCG(128, N, 2, 2, c, t)
	assert.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pcg.genSingleOlePCG()
		assert.Nil(b, err)
	}
}

func benchmarkSingleOLEpcgEvaluation(b *testing.B, N, c, t int) {
	log.Printf("------------------- BENCHMARK SINGLE PCG OLE --------------------")
	log.Printf("N: %d, c: %d, t: %d\n", N, c, t)

	pcg, err := NewPCG(128, N, 2, 2, c, t)
	assert.Nil(b, err)

	seeds, err := pcg.genSingleOlePCG()
	assert.Nil(b, err)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(b, err)

	ring, err := pcg.GetRing(false)
	assert.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := pcg.evalSingleOle(seeds[0], randPolys, ring.Div)
		assert.Nil(b, err)
	}
}

func benchmarkSingleVOLEpcgGeneration(b *testing.B, N, c, t int) {
	pcg, err := NewPCG(128, N, 2, 2, c, t)
	assert.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pcg.genSingleVolePCG()
		assert.Nil(b, err)
	}
}

func benchmarkSingleVOLEpcgEvaluation(b *testing.B, N, c, t int) {
	log.Printf("------------------- BENCHMARK SINGLE PCG VOLE --------------------")
	log.Printf("N: %d, c: %d, t: %d\n", N, c, t)

	pcg, err := NewPCG(128, N, 2, 2, c, t)
	assert.Nil(b, err)

	seeds, err := pcg.genSingleVolePCG()
	assert.Nil(b, err)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(b, err)

	ring, err := pcg.GetRing(false)
	assert.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := pcg.evalSingleVole(seeds[0], randPolys, ring.Div)
		assert.Nil(b, err)
	}
}
