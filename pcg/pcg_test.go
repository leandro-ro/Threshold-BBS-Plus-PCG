package pcg

import (
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestPCGCentralizedGen(t *testing.T) {
	pcg, err := NewPCG(128, 20, 2, 4, 16)
	assert.Nil(t, err)

	_, err = pcg.TrustedSeedGen()
	assert.Nil(t, err)
}

func TestPCGGen(t *testing.T) {
	pcg, err := NewPCG(128, 12, 2, 4, 16)
	assert.Nil(t, err)

	seeds, err := pcg.TrustedSeedGen()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	eval0, err := pcg.Eval(seeds[0], randPolys)
	assert.Nil(t, err)
	assert.NotNil(t, eval0)
	eval1, err := pcg.Eval(seeds[1], randPolys)
	assert.Nil(t, err)
	assert.NotNil(t, eval1)

	keyNr := 15
	a := bls12381.NewFr()
	a.Add(eval0[keyNr].AShare, eval1[keyNr].AShare)

	s := bls12381.NewFr()
	s.Add(eval0[keyNr].SShare, eval1[keyNr].SShare)

	e := bls12381.NewFr()
	e.Add(eval0[keyNr].EShare, eval1[keyNr].EShare)

	alpha := bls12381.NewFr()
	alpha.Add(eval0[1].AlphaShare, eval1[1].AlphaShare)

	delta := bls12381.NewFr()
	delta.Add(eval0[keyNr].DeltaShare, eval1[keyNr].DeltaShare)

	as := bls12381.NewFr()
	as.Mul(a, s)

	sk := bls12381.NewFr()
	sk.Add(eval0[keyNr].SkShare, eval1[keyNr].SkShare)

	assert.Equal(t, 0, alpha.Cmp(as))

	ask := bls12381.NewFr()
	ask.Mul(a, sk)

	ae := bls12381.NewFr()
	ae.Mul(a, e)

	aske := bls12381.NewFr()
	aske.Add(ask, ae)

	assert.Equal(t, 0, delta.Cmp(aske))
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
