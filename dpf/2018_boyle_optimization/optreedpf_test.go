package optreedpf_test

import (
	"crypto/rand"
	bn254_fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
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
	x, _ = new(big.Int).SetString("100276378814221914538187675173181300605", 10)
	wx, _ := rand.Int(rand.Reader, maxInput)
	y, _ := rand.Int(rand.Reader, d.Curve.BaseField()) // Max input is the base field size
	y, _ = new(big.Int).SetString("2222596145900766452236097888800300647832423168503314259268217808888195720797", 10)

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

func TestArithmetics(t *testing.T) {
	FinalSeedAlice, _ := new(bn254_fp.Element).SetString("6424070194096219131817711689373532512314348505857030959234270882748282479583")
	FinalSeedBob, _ := new(bn254_fp.Element).SetString("9473302291442315411670644815354219180829833492338768502962556545805604934639")
	CW, _ := new(bn254_fp.Element).SetString("13674776339637768091252258615927451045311758829692485202928609619665691693425")
	beta, _ := new(bn254_fp.Element).SetString("2222596145900766452236097888800300647832423168503314259268217808888195720797")
	//t_alice := false
	//t_bob := true
	AlicePartRes, _ := new(bn254_fp.Element).SetString("6424070194096219131817711689373532512314348505857030959234270882748282479583")
	BobPartRes, _ := new(bn254_fp.Element).SetString("20628407112598466941569908059232879951251029992564393619486909623819155789102")

	//checkCW := new(bn254_fp.Element).Add(FinalSeedAlice, FinalSeedBob)
	//checkCW = checkCW.Sub(beta, checkCW)
	//checkCW = checkCW.Neg(checkCW)
	checkCW := new(bn254_fp.Element).Sub(beta, FinalSeedAlice)
	checkCW = checkCW.Add(checkCW, FinalSeedBob)
	checkCW = checkCW.Neg(checkCW)
	assert.Equal(t, CW.String(), checkCW.String())

	alice := FinalSeedAlice
	assert.Equal(t, AlicePartRes.String(), alice.String())

	bob := FinalSeedBob.Add(FinalSeedBob, CW)
	bob = bob.Neg(bob)
	assert.Equal(t, BobPartRes.String(), bob.String())

	sum := alice.Add(alice, bob)
	assert.Equal(t, beta.String(), sum.String())

}
