package optreedpf_test

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	optreedpf "pcg-master-thesis/dpf/2018_boyle_optimization"

	"testing"
)

func TestOpTreeDPFInitialization(t *testing.T) {
	d1, err1 := optreedpf.InitFactory(128, 128)
	assert.Nil(t, err1)
	assert.NotNil(t, d1)

	d2, err2 := optreedpf.InitFactory(192, 192)
	assert.Nil(t, err2)
	assert.NotNil(t, d2)

	d3, err3 := optreedpf.InitFactory(256, 256)
	assert.Nil(t, err3)
	assert.NotNil(t, d3)

	d4, err4 := optreedpf.InitFactory(5, 5)
	assert.NotNil(t, err4)
	assert.Nil(t, d4)
}

func TestOpTreeDPFKeySerializationAndDeserialization(t *testing.T) {
	d, _ := optreedpf.InitFactory(128, 128)

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

func TestOpTreeDPFGenAndEval128(t *testing.T) {
	testOpTreeDPFGenAndEval(t, 128, 128)
}

func TestOpTreeDPFGenAndEval192(t *testing.T) {
	testOpTreeDPFGenAndEval(t, 192, 192)
}

func TestOpTreeDPFGenAndEval256(t *testing.T) {
	testOpTreeDPFGenAndEval(t, 256, 256)
}

func TestOpTreeDPFStress(t *testing.T) {
	lambda := 256
	domain := 256
	d, err := optreedpf.InitFactory(lambda, domain)
	assert.Nil(t, err)

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)

	for i := 0; i < 500; i++ {
		x, _ := rand.Int(rand.Reader, maxInputX)
		y, _ := rand.Int(rand.Reader, d.BetaMax)

		k1, k2, err := d.Gen(x, y)
		assert.Nil(t, err)

		res1, err := d.Eval(k1, x)
		assert.Nil(t, err)

		res2, err := d.Eval(k2, x)
		assert.Nil(t, err)

		result := d.CombineResults(res1, res2)
		assert.Equal(t, y, result)
	}
}

func TestOpTreeDPFGenAndEvalToZero(t *testing.T) {
	lambda := 128
	domain := 64
	d, err := optreedpf.InitFactory(lambda, domain)
	assert.Nil(t, err)

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)
	maxInputY := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)

	x, _ := rand.Int(rand.Reader, maxInputX)
	wx1, _ := rand.Int(rand.Reader, maxInputX)
	wx2, _ := rand.Int(rand.Reader, maxInputX)
	wx3, _ := rand.Int(rand.Reader, maxInputX)
	zero := big.NewInt(0)

	y, _ := rand.Int(rand.Reader, maxInputY)

	k1, k2, err := d.Gen(x, y)
	assert.Nil(t, err)

	res1, err := d.Eval(k1, x)
	assert.Nil(t, err)
	res2, err := d.Eval(k2, x)
	assert.Equal(t, y, d.CombineResults(res1, res2))

	res1, err = d.Eval(k1, wx1)
	assert.Nil(t, err)
	res2, err = d.Eval(k2, wx1)
	assert.Nil(t, err)
	assert.Equal(t, 0, d.CombineResults(res1, res2).Cmp(zero))

	res1, err = d.Eval(k1, wx2)
	assert.Nil(t, err)
	res2, err = d.Eval(k2, wx2)
	assert.Nil(t, err)
	assert.Equal(t, 0, d.CombineResults(res1, res2).Cmp(zero))

	res1, err = d.Eval(k1, wx3)
	assert.Nil(t, err)
	res2, err = d.Eval(k2, wx3)
	assert.Nil(t, err)
	assert.Equal(t, 0, d.CombineResults(res1, res2).Cmp(zero))
}

func testOpTreeDPFGenAndEval(t *testing.T, lambda int, domain int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	assert.Nil(t, err)

	maxInput := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInput)
	wx, _ := rand.Int(rand.Reader, maxInput)
	y, _ := rand.Int(rand.Reader, d.BetaMax) // Max input is the base field size

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

func TestOpTreeDPFFullEval128(t *testing.T) {
	testOpTreeDPFFullEval(t, 128, 10) // Using small domains here as FullEval is computationally expensive
}

func TestOpTreeDPFFullEval192(t *testing.T) {
	testOpTreeDPFFullEval(t, 192, 12) // Using small domains here as FullEval is computationally expensive
}

func TestOpTreeDPFFullEval256(t *testing.T) {
	testOpTreeDPFFullEval(t, 256, 14) // Using small domains here as FullEval is computationally expensive
}

func testOpTreeDPFFullEval(t *testing.T, lambda int, domain int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	assert.Nil(t, err)

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)
	x, _ := rand.Int(rand.Reader, maxInputX)
	y, _ := rand.Int(rand.Reader, d.BetaMax) // Max input is the base field size

	k1, k2, err := d.Gen(x, y)
	assert.Nil(t, err)

	res1, err := d.FullEval(k1)
	assert.Nil(t, err)

	res2, err := d.FullEval(k2)
	assert.Nil(t, err)

	res, err := d.CombineMultipleResults(res1, res2)
	assert.Nil(t, err)

	// Check that only one element is not zero and is equal to y
	nonZeroCount := 0
	for _, val := range res {
		if val.Cmp(big.NewInt(0)) != 0 { // val is not zero
			nonZeroCount++
			assert.Equal(t, y, val, "The non-zero value should be equal to y")
		}
	}

	assert.Equal(t, 1, nonZeroCount, "There should be exactly one non-zero value in the result")
}

func TestOpTreeDPFFullEvalFast128(t *testing.T) {
	testOpTreeDPFFullEvalParallel(t, 128, 10) // Using small domains here as FullEval is computationally expensive
}

func TestOpTreeDPFFullEvalFast192(t *testing.T) {
	testOpTreeDPFFullEvalParallel(t, 192, 12) // Using small domains here as FullEval is computationally expensive
}

func TestOpTreeDPFFullEvalFast256(t *testing.T) {
	testOpTreeDPFFullEvalParallel(t, 256, 14) // Using small domains here as FullEval is computationally expensive
}

func testOpTreeDPFFullEvalParallel(t *testing.T, lambda int, domain int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	assert.Nil(t, err)

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)
	x, _ := rand.Int(rand.Reader, maxInputX)
	y, _ := rand.Int(rand.Reader, d.BetaMax) // Max input is the base field size

	k1, k2, err := d.Gen(x, y)
	assert.Nil(t, err)

	res1, err := d.FullEvalFast(k1)
	assert.Nil(t, err)

	res2, err := d.FullEvalFast(k2)
	assert.Nil(t, err)

	res, err := d.CombineMultipleResults(res1, res2)
	assert.Nil(t, err)

	// Check that only one element is not zero and is equal to y
	nonZeroCount := 0
	for _, val := range res {
		if val.Cmp(big.NewInt(0)) != 0 { // val is not zero
			nonZeroCount++
			assert.Equal(t, y, val, "The non-zero value should be equal to y")
		}
	}

	assert.Equal(t, 1, nonZeroCount, "There should be exactly one non-zero value in the result")
}

// Benchmarks:
func BenchmarkOpTreeDPFGen128_n32(b *testing.B)  { benchmarkOpTreeDPFGen(b, 128, 32) }
func BenchmarkOpTreeDPFGen128_n64(b *testing.B)  { benchmarkOpTreeDPFGen(b, 128, 64) }
func BenchmarkOpTreeDPFGen128_n128(b *testing.B) { benchmarkOpTreeDPFGen(b, 128, 128) }

func BenchmarkOpTreeDPFGen192_n32(b *testing.B)  { benchmarkOpTreeDPFGen(b, 192, 32) }
func BenchmarkOpTreeDPFGen192_n64(b *testing.B)  { benchmarkOpTreeDPFGen(b, 192, 64) }
func BenchmarkOpTreeDPFGen192_n128(b *testing.B) { benchmarkOpTreeDPFGen(b, 192, 128) }

func BenchmarkOpTreeDPFGen256_n32(b *testing.B)  { benchmarkOpTreeDPFGen(b, 256, 32) }
func BenchmarkOpTreeDPFGen256_n64(b *testing.B)  { benchmarkOpTreeDPFGen(b, 256, 64) }
func BenchmarkOpTreeDPFGen256_n128(b *testing.B) { benchmarkOpTreeDPFGen(b, 256, 128) }

func BenchmarkOpTreeDPFEval128_n32(b *testing.B)  { benchmarkOpTreeDPFEval(b, 128, 32) }
func BenchmarkOpTreeDPFEval128_n64(b *testing.B)  { benchmarkOpTreeDPFEval(b, 128, 64) }
func BenchmarkOpTreeDPFEval128_n128(b *testing.B) { benchmarkOpTreeDPFEval(b, 128, 128) }

func BenchmarkOpTreeDPFEval192_n32(b *testing.B)  { benchmarkOpTreeDPFEval(b, 192, 32) }
func BenchmarkOpTreeDPFEval192_n64(b *testing.B)  { benchmarkOpTreeDPFEval(b, 192, 64) }
func BenchmarkOpTreeDPFEval192_n128(b *testing.B) { benchmarkOpTreeDPFEval(b, 192, 128) }

func BenchmarkOpTreeDPFEval256_n32(b *testing.B)  { benchmarkOpTreeDPFEval(b, 256, 32) }
func BenchmarkOpTreeDPFEval256_n64(b *testing.B)  { benchmarkOpTreeDPFEval(b, 256, 64) }
func BenchmarkOpTreeDPFEval256_n128(b *testing.B) { benchmarkOpTreeDPFEval(b, 256, 128) }

func BenchmarkOpTreeDPFFullEval128_n10(b *testing.B)     { benchmarkOpTreeDPFFullEval(b, 128, 10) }
func BenchmarkOpTreeDPFFullEvalFast128_n10(b *testing.B) { benchmarkOpTreeDPFFullEvalFast(b, 128, 10) }

func BenchmarkOpTreeDPFFullEval128_n16(b *testing.B)     { benchmarkOpTreeDPFFullEval(b, 128, 16) }
func BenchmarkOpTreeDPFFullEvalFast128_n16(b *testing.B) { benchmarkOpTreeDPFFullEvalFast(b, 128, 16) }

func BenchmarkOpTreeDPFFullEval128_n17(b *testing.B)     { benchmarkOpTreeDPFFullEval(b, 128, 17) }
func BenchmarkOpTreeDPFFullEvalFast128_n17(b *testing.B) { benchmarkOpTreeDPFFullEvalFast(b, 128, 17) }

func BenchmarkOpTreeDPFFullEval128_n18(b *testing.B)     { benchmarkOpTreeDPFFullEval(b, 128, 18) }
func BenchmarkOpTreeDPFFullEvalFast128_n18(b *testing.B) { benchmarkOpTreeDPFFullEvalFast(b, 128, 18) }

func BenchmarkOpTreeDPFFullEval128_n19(b *testing.B)     { benchmarkOpTreeDPFFullEval(b, 128, 19) }
func BenchmarkOpTreeDPFFullEvalFast128_n19(b *testing.B) { benchmarkOpTreeDPFFullEvalFast(b, 128, 19) }

func BenchmarkOpTreeDPFFullEval128_n20(b *testing.B)     { benchmarkOpTreeDPFFullEval(b, 128, 20) }
func BenchmarkOpTreeDPFFullEvalFast128_n20(b *testing.B) { benchmarkOpTreeDPFFullEvalFast(b, 128, 20) }

func BenchmarkOpTreeDPFFullEval128_n21(b *testing.B)     { benchmarkOpTreeDPFFullEval(b, 128, 21) }
func BenchmarkOpTreeDPFFullEvalFast128_n21(b *testing.B) { benchmarkOpTreeDPFFullEvalFast(b, 128, 21) }

func benchmarkOpTreeDPFGen(b *testing.B, lambda, domain int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	if err != nil {
		b.Fatal(err)
	}

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)
	maxInputY := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInputX)
	y, _ := rand.Int(rand.Reader, maxInputY)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := d.Gen(x, y)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOpTreeDPFEval(b *testing.B, lambda, domain int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	if err != nil {
		b.Fatal(err)
	}

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)
	maxInputY := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInputX)
	y, _ := rand.Int(rand.Reader, maxInputY)

	k1, _, err := d.Gen(x, y)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.Eval(k1, x)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOpTreeDPFFullEval(b *testing.B, lambda, domain int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	if err != nil {
		b.Fatal(err)
	}

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)
	maxInputY := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInputX)
	y, _ := rand.Int(rand.Reader, maxInputY)

	k1, _, err := d.Gen(x, y)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.FullEval(k1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOpTreeDPFFullEvalFast(b *testing.B, lambda, domain int) {
	d, err := optreedpf.InitFactory(lambda, domain)
	if err != nil {
		b.Fatal(err)
	}

	maxInputX := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(domain)), nil)
	maxInputY := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	x, _ := rand.Int(rand.Reader, maxInputX)
	y, _ := rand.Int(rand.Reader, maxInputY)

	k1, _, err := d.Gen(x, y)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.FullEvalFast(k1)
		if err != nil {
			b.Fatal(err)
		}
	}
}
