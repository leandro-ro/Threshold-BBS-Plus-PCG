package pcg

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

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
