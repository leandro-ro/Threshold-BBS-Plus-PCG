package ffarithmetics

// Importing necessary packages
import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"pcg-master-thesis/dpf"
	"testing"
)

func TestNewGF2M(t *testing.T) {
	// Test for valid m
	g, err := NewGF2M(7)
	if err != nil {
		t.Errorf("NewGF2M(7) returned an error: %v", err)
	}
	if g.Modulus == nil {
		t.Errorf("NewGF2M(7) returned nil Modulus")
	}
}

func TestGF2MAdd(t *testing.T) {
	g, err := NewGF2M(131)
	if err != nil {
		t.Errorf("NewGF2M(129) returned an error: %v", err)
	}
	a := big.NewInt(10)
	b := big.NewInt(20)

	result := g.Add(a, b)
	expectedResult := big.NewInt(30)
	if result.Cmp(expectedResult) != 0 {
		t.Errorf("Add(10, 20) = %v; want %v", result, expectedResult)
	}
}

func TestGF2MMul(t *testing.T) {
	g, err := NewGF2M(131)
	if err != nil {
		t.Errorf("NewGF2M(129) returned an error: %v", err)
	}
	a := big.NewInt(10)
	b := big.NewInt(20)

	result := g.Mul(a, b)
	expectedResult := big.NewInt(200) // Assuming modulus is large enough
	if result.Cmp(expectedResult) != 0 {
		t.Errorf("Mul(10, 20) = %v; want %v", result, expectedResult)
	}
}

func TestGF2MInv(t *testing.T) {
	g, err := NewGF2M(131)
	if err != nil {
		t.Errorf("NewGF2M(129) returned an error: %v", err)
	}
	a := big.NewInt(4)
	result := g.Inv(a)
	if result == nil {
		t.Errorf("Inv(4) returned nil")
	}

	// Validate the inverse by multiplying it with the original number and reducing modulo the field
	check := g.Mul(a, result)
	if check.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Inv(3) did not return a valid multiplicative inverse. Got %v", result)
	}
}

func TestGF2MInvNonCoprime(t *testing.T) {
	g, err := NewGF2M(131)
	if err != nil {
		t.Errorf("NewGF2M(129) returned an error: %v", err)
	}
	a := big.NewInt(3)
	result := g.Inv(a)
	if result != nil {
		t.Errorf("A is not coprime to modulus")
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
	sumInv := gf2m.Inv(sum)
	w := gf2m.Mul(sumInv, b)

	recAlice := gf2m.Mul(w, alice)
	recBob := gf2m.Mul(w, bob)

	rec := gf2m.Add(recAlice, recBob)

	assert.Equal(t, b, rec)
}
