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
	pcg, err := NewPCG(128, 15, 2, 4, 8)
	assert.Nil(t, err)

	seeds, err := pcg.CentralizedGen()
	assert.Nil(t, err)
	assert.NotNil(t, seeds)

	eval0, err := pcg.Eval(seeds[0])
	assert.Nil(t, err)
	assert.NotNil(t, eval0)
}
