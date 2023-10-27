package treedpf_test

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	treedpf "pcg-master-thesis/dpf/2015_boyle_tree_based"
	"testing"
)

func TestTreeDPFInitialization(t *testing.T) {
	d, err := treedpf.GetTreeDPF(128)
	assert.Nil(t, err)
	assert.NotNil(t, d)
}

func TestTreeDPFKeySerializationAndDeserialization(t *testing.T) {
	d, _ := treedpf.GetTreeDPF(128)

	x := big.NewInt(5)
	y := big.NewInt(10)

	k1, _, err := d.Gen(x, y)
	assert.Nil(t, err)

	serialized, err := k1.Serialize()
	assert.Nil(t, err)

	var deserialized treedpf.Key
	err = deserialized.Deserialize(serialized)
	assert.Nil(t, err)

	assert.Equal(t, k1, deserialized)
}

func TestTreeDPFGenAndEval(t *testing.T) {
	d, _ := treedpf.GetTreeDPF(128)

	x := big.NewInt(5)
	y := big.NewInt(10)

	k1, k2, err := d.Gen(x, y)
	assert.Nil(t, err)

	res1, err := d.Eval(k1, x)
	assert.Nil(t, err)
	assert.Equal(t, y, res1)

	res2, err := d.Eval(k2, x)
	assert.Nil(t, err)
	assert.Equal(t, y, res2)
}

// Add more test cases here to cover edge cases, errors, and so on.
