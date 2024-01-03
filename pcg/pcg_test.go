package pcg

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPCGCentralizedGen(t *testing.T) {
	pcg, err := NewPCG(128, 20, 2, 4, 16)
	assert.Nil(t, err)

	_, err = pcg.CentralizedGen()
	assert.Nil(t, err)
}

func TestPCGGen(t *testing.T) {
	pcg, err := NewPCG(128, 10, 2, 2, 4)
	assert.Nil(t, err)

	seeds, err := pcg.CentralizedGen()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	randPolys, err := pcg.PickRandomPolynomials()
	assert.Nil(t, err)
	assert.NotNil(t, randPolys)

	eval0, err := pcg.Eval(seeds[0], randPolys)
	assert.Nil(t, err)
	assert.NotNil(t, eval0)
}
