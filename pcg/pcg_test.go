package pcg

import (
	"github.com/stretchr/testify/assert"
	optreedpf "pcg-master-thesis/dpf/2018_boyle_optimization"
	"testing"
)

func TestPCGCentralizedGen(t *testing.T) {
	dpf, err := optreedpf.InitFactory(128, 10)
	assert.Nil(t, err)

	pcg := NewPCG(128, 20, 2, 4, 16, dpf)
	assert.Nil(t, err)

	_, err = pcg.CentralizedGen()
	assert.Nil(t, err)
}
