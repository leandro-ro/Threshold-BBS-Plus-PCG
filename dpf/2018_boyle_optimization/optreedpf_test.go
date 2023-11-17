package optreedpf_test

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	optreedpf "pcg-master-thesis/dpf/2018_boyle_optimization"

	"testing"
)

func TestTreeDPFInitialization(t *testing.T) {
	d1, err1 := optreedpf.InitFactory(128)
	assert.Nil(t, err1)
	assert.NotNil(t, d1)

	d2, err2 := optreedpf.InitFactory(192)
	assert.Nil(t, err2)
	assert.NotNil(t, d2)

	d3, err3 := optreedpf.InitFactory(256)
	assert.Nil(t, err3)
	assert.NotNil(t, d3)

	d4, err4 := optreedpf.InitFactory(5)
	assert.NotNil(t, err4)
	assert.Nil(t, d4)
}

func TestTreeDPFKeySerializationAndDeserialization(t *testing.T) {
	d, _ := optreedpf.InitFactory(128)

	x := big.NewInt(5)
	y := big.NewInt(10)

	k1, _, err := d.Gen(x, y)
	assert.Nil(t, err)

	serialized, err := k1.Serialize()
	assert.Nil(t, err)

	deserialized := new(optreedpf.Key)
	err = deserialized.Deserialize(serialized)
	assert.Nil(t, err)

	assert.Equal(t, k1, deserialized)
}

func TestTreeDPFGenAndEval128(t *testing.T) {
	lambda := 128
	d, err := optreedpf.InitFactory(lambda)
	assert.Nil(t, err)

	maxInput := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInput)
	wx, _ := rand.Int(rand.Reader, maxInput)
	y, _ := rand.Int(rand.Reader, d.Curve.BaseField()) // Max input is the base field size

	k1, k2, err := d.Gen(x, y)
	assert.Nil(t, err)

	res1, err := d.Eval(k1, wx)
	assert.Nil(t, err)

	res2, err := d.Eval(k2, wx)
	assert.Nil(t, err)

	result1 := d.CombineResults(res1, res2)
	assert.True(t, big.NewInt(0).Cmp(result1) == 0)

	res3, err := d.Eval(k1, x)
	assert.Nil(t, err)

	res4, err := d.Eval(k2, x)
	assert.Nil(t, err)

	result2 := d.CombineResults(res3, res4)
	assert.Equal(t, y, result2)
}
