package ffarithmetics

// Importing necessary packages
import (
	"crypto/rand"
	"errors"
	"github.com/stretchr/testify/assert"
	"math/big"
	"pcg-master-thesis/dpf"
	"testing"
)

func TestNewGF2M(t *testing.T) {
	// Test for valid m
	g, err := NewGF2M(128)
	if err != nil {
		t.Errorf("NewGF2M(128) returned an error: %v", err)
	}
	if g.Modulus == nil {
		t.Errorf("NewGF2M(128) returned nil Modulus")
	}
}

func TestGF2MSubEqAdd(t *testing.T) {
	g, err := NewGF2M(128)
	if err != nil {
		t.Errorf("NewGF2M(128) returned an error: %v", err)
	}
	a := big.NewInt(1261)
	b := big.NewInt(1261)

	result := g.Add(a, b)
	expectedResult := big.NewInt(0)
	if result.Cmp(expectedResult) != 0 {
		t.Errorf("Add(1261, 1261) = %v; want %v", result, expectedResult)
	}
}

func TestGF2MMul(t *testing.T) {
	gf2m, err := NewGF2M(128)
	if err != nil {
		t.Fatalf("Failed to create GF2M: %v", err)
	}

	// Test the associative property a*(b*c) == (a*b)*c
	a := big.NewInt(123456789)
	b := big.NewInt(987654321)
	c := big.NewInt(192837465)

	ab := gf2m.Mul(a, b)
	abc := gf2m.Mul(ab, c)

	bc := gf2m.Mul(b, c)
	abc2 := gf2m.Mul(a, bc)

	if abc.Cmp(abc2) != 0 {
		t.Errorf("Associative property of multiplication failed: (a*b)*c != a*(b*c)")
	}

	// Test the distributive property a*(b+c) == (a*b) + (a*c)
	bPlusC := gf2m.Add(b, c)
	aTimesBPlusC := gf2m.Mul(a, bPlusC)

	aTimesB := gf2m.Mul(a, b)
	aTimesC := gf2m.Mul(a, c)
	aTimesBPlusATimesC := gf2m.Add(aTimesB, aTimesC)

	if aTimesBPlusC.Cmp(aTimesBPlusATimesC) != 0 {
		t.Errorf("Distributive property of multiplication failed: a*(b+c) != (a*b) + (a*c)")
	}

	// Test multiplication by 1 (the multiplicative identity)
	one := big.NewInt(1)
	aTimesOne := gf2m.Mul(a, one)

	if a.Cmp(aTimesOne) != 0 {
		t.Errorf("Multiplication by one failed: a * 1 != a")
	}

	// Test multiplication by 0
	zero := big.NewInt(0)
	aTimesZero := gf2m.Mul(a, zero)

	if zero.Cmp(aTimesZero) != 0 {
		t.Errorf("Multiplication by zero failed: a * 0 != 0")
	}
}

func TestGF2MInv(t *testing.T) {
	gf2m, err := NewGF2M(128)
	if err != nil {
		t.Fatalf("Failed to create GF2M: %v", err)
	}

	// Calculate the inverse of 'a'
	a := big.NewInt(123456789)

	aInv, err := gf2m.Inv(a)
	if err != nil {
		t.Errorf("Failed to find the inverse of a: %v", err)
	}

	// Multiply 'a' by its inverse and reduce it
	result := gf2m.Mul(a, aInv)

	// The result should be '1'
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Multiplicative inverse property failed for a: %s, a^-1: %s, a * a^-1: %s",
			a.Text(16), aInv.Text(16), result.Text(16))
	}
}

func TestArithmetics(t *testing.T) {
	b := new(big.Int)
	b.SetString("123123123123123123123123", 10)

	str := "2932339756623750898567482807483427578180007451514938164616853887300592835533774"
	alice := new(big.Int)
	alice.SetString(str, 10)

	str = "15843769400890255621027114878557118005034414476166066718927349442239871701439695"
	bob := new(big.Int)
	bob.SetString(str, 10)

	gf2m, err := NewGF2M(dpf.NextOddPrime(128))
	if err != nil {
		assert.Nil(t, err)
	}

	sum := gf2m.Add(alice, bob)
	sumInv, _ := gf2m.Inv(sum)
	w := gf2m.Mul(sumInv, b)

	recAlice := gf2m.Mul(w, alice)
	recBob := gf2m.Mul(w, bob)

	rec := gf2m.Add(recAlice, recBob)

	assert.Equal(t, b, rec)
}

// randNonZeroBigInt generates a random non-zero big.Int less than a given bit length.
func randNonZeroBigInt(bitLen int) (*big.Int, error) {
	if bitLen <= 0 {
		return nil, errors.New("bit length must be positive")
	}

	randBigInt := new(big.Int)
	var err error
	for randBigInt.Sign() == 0 { // Ensure it's non-zero
		randBigInt, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bitLen)))
		if err != nil {
			return nil, err
		}
	}
	return randBigInt, nil
}
