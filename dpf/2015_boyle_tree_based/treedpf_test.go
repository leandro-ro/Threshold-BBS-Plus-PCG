package treedpf_test

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	treedpf "pcg-master-thesis/dpf/2015_boyle_tree_based"
	"testing"
)

func TestTreeDPFInitialization(t *testing.T) {
	d1, err1 := treedpf.InitFactory(128)
	assert.Nil(t, err1)
	assert.NotNil(t, d1)

	d2, err2 := treedpf.InitFactory(192)
	assert.Nil(t, err2)
	assert.NotNil(t, d2)

	d3, err3 := treedpf.InitFactory(256)
	assert.Nil(t, err3)
	assert.NotNil(t, d3)

	d4, err4 := treedpf.InitFactory(5)
	assert.NotNil(t, err4)
	assert.Nil(t, d4)
}

func TestTreeDPFKeySerializationAndDeserialization(t *testing.T) {
	d, _ := treedpf.InitFactory(128)

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

func TestTreeDPFGenAndEval128(t *testing.T) {
	lambda := 128
	d, err := treedpf.InitFactory(lambda)
	assert.Nil(t, err)

	maxInput := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInput)
	y, _ := rand.Int(rand.Reader, maxInput)

	k1, k2, err := d.Gen(x, y)
	assert.Nil(t, err)

	res1, err := d.Eval(k1, x)
	assert.Nil(t, err)

	res2, err := d.Eval(k2, x)
	assert.Nil(t, err)

	result := d.CombineResults(res1, res2)
	assert.Equal(t, y, result)
}

func TestTreeDPFGenAndEval192(t *testing.T) {
	lambda := 192
	d, err := treedpf.InitFactory(lambda)
	assert.Nil(t, err)

	maxInput := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInput)
	y, _ := rand.Int(rand.Reader, maxInput)

	k1, k2, err := d.Gen(x, y)
	assert.Nil(t, err)

	res1, err := d.Eval(k1, x)
	assert.Nil(t, err)

	res2, err := d.Eval(k2, x)
	assert.Nil(t, err)

	result := d.CombineResults(res1, res2)
	assert.Equal(t, y, result)

	wrongx, _ := rand.Int(rand.Reader, maxInput)
	res3, err := d.Eval(k1, wrongx)
	assert.Nil(t, err)

	res4, err := d.Eval(k2, wrongx)
	assert.Nil(t, err)

	wrong_result := d.CombineResults(res3, res4)
	assert.NotEqual(t, result, wrong_result)
}

func TestTreeDPFGenAndEval256(t *testing.T) {
	lambda := 256
	d, err := treedpf.InitFactory(lambda)
	assert.Nil(t, err)

	maxInput := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInput)
	y, _ := rand.Int(rand.Reader, maxInput)

	k1, k2, err := d.Gen(x, y)
	assert.Nil(t, err)

	res1, err := d.Eval(k1, x)
	assert.Nil(t, err)

	res2, err := d.Eval(k2, x)
	assert.Nil(t, err)

	result := d.CombineResults(res1, res2)
	assert.Equal(t, y, result)
}
