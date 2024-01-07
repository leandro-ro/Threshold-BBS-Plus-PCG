package pcg

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestPCGCentralizedGen(t *testing.T) {
	pcg, err := NewPCG(128, 20, 2, 4, 4)
	assert.Nil(t, err)

	_, err = pcg.TrustedSeedGen()
	assert.Nil(t, err)
}

func TestPCGGen(t *testing.T) {
	pcg, err := NewPCG(128, 9, 2, 2, 4)
	assert.Nil(t, err)

	seeds, err := pcg.TrustedSeedGen()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)
	fmt.Println("Seed finished")

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	ring, err := pcg.GetRing(true)
	assert.Nil(t, err)
	assert.NotNil(t, ring)

	eval0, err := pcg.Eval(seeds[0], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval0)
	fmt.Println("Eval0 finished")

	eval1, err := pcg.Eval(seeds[1], randPolys, ring.Div)
	assert.Nil(t, err)
	assert.NotNil(t, eval1)
	fmt.Println("Eval1 finished")

	keyNr := 2
	root := ring.Roots[keyNr]

	tuple0 := eval0.GenBBSPlusTuple(root)
	tuple1 := eval1.GenBBSPlusTuple(root)

	sk := bls12381.NewFr()
	sk.Add(tuple0.SkShare, tuple1.SkShare)

	seedSk := bls12381.NewFr()
	seedSk.Add(seeds[0].ski, seeds[1].ski)
	assert.Equal(t, 0, sk.Cmp(seedSk))

	a := bls12381.NewFr()
	a.Add(tuple0.AShare, tuple1.AShare)

	s := bls12381.NewFr()
	s.Add(tuple0.SShare, tuple1.SShare)

	e := bls12381.NewFr()
	e.Add(tuple0.EShare, tuple1.EShare)

	alpha := bls12381.NewFr()
	alpha.Add(tuple0.AlphaShare, tuple1.AlphaShare)

	delta0 := bls12381.NewFr() // delta0 = ask
	delta0.Add(tuple0.Delta0Share, tuple1.Delta0Share)

	delta1 := bls12381.NewFr() // delta1 = ae
	delta1.Add(tuple0.Delta1Share, tuple1.Delta1Share)

	delta := bls12381.NewFr()
	delta.Add(tuple0.DeltaShare, tuple1.DeltaShare)

	ask := bls12381.NewFr()
	ask.Mul(a, sk)

	ae := bls12381.NewFr()
	ae.Mul(a, e)

	as := bls12381.NewFr()
	as.Mul(a, s)

	assert.Equal(t, 0, ae.Cmp(delta1)) // OLE Correlations are working as expected
	assert.Equal(t, 0, alpha.Cmp(as))
	assert.Equal(t, 0, ask.Cmp(delta0)) // TODO: This test fails
}

func TestPCGGenVOLE(t *testing.T) {
	pcg, err := NewPCG(128, 10, 2, 4, 16)
	assert.Nil(t, err)

	seeds, err := pcg.SeedGenVOLE()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	ring, err := pcg.GetRing(true)
	assert.Nil(t, err)
	assert.NotNil(t, ring)

	a0, delta0, err := pcg.EvalVOLE(seeds[0], randPolys, ring.Div)
	a1, delta1, err := pcg.EvalVOLE(seeds[1], randPolys, ring.Div)

	sk := bls12381.NewFr()
	sk.Add(seeds[0].ski, seeds[1].ski)

	keyNr := 2
	root := ring.Roots[keyNr]

	a0Eval := a0.Evaluate(root)
	a1Eval := a1.Evaluate(root)

	a := bls12381.NewFr()
	a.Add(a0Eval, a1Eval)

	detla0Eval := delta0.Evaluate(root)
	delta1Eval := delta1.Evaluate(root)

	delta := bls12381.NewFr()
	delta.Add(detla0Eval, delta1Eval) // should be equal to ask

	ask := bls12381.NewFr()
	ask.Mul(a, sk)

	assert.Equal(t, 0, ask.Cmp(delta))
}

func TestBLS12381GroupOrderFactorization(t *testing.T) {
	// BSLS12381 group order - 1
	expected := new(big.Int)
	expected.SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	expected.Sub(expected, big.NewInt(1))

	factorization := multiplicativeGroupOrderFactorizationBLS12381()

	// Multiply all factors together
	product := big.NewInt(1)
	for _, pf := range factorization {
		val := big.NewInt(0)
		val.Exp(pf.Factor, big.NewInt(int64(pf.Exponent)), nil)
		product.Mul(product, val)
	}

	assert.Equal(t, 0, expected.Cmp(product))
}
