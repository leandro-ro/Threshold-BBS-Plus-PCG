// Package ffarithmetics provides GF(2^m) arithmetics.
//
// The library provides functionality to add, multiply,
// and find the multiplicative inverse in the field GF(2^m).
package ffarithmetics

import (
	"errors"
	"fmt"
	"math/big"
)

// Irreducible Polynomials for GF(2^m) taken from "Table of Low-Weight Binary Irreducible Polynomials"
// by Gadiel Seroussi, https://www.hpl.hp.com/techreports/98/HPL-98-135.pdf

const IrreduciblePoly128 = "340282366920938463463374607431768211590"                                        // "x^128 + x^7 + x^2 + x + 1"
const IrreduciblePoly192 = "6277101735386680763835789423207666416102355444464034513030"                     // "x^192 + x^7 + x^2 + x + 1"
const IrreduciblePoly256 = "115792089237316195423570985008687907853269984665640564039457584007913129640998" // "x^256 + x^10 + x^5 + x^2 + 1"

// GF2M represents a field GF(2^m).
type GF2M struct {
	Modulus *big.Int // Modulus is the irreducible polynomial for the field GF(2^m).
}

// NewGF2M constructs a new GF2M struct which can then be used for calculations inside GF(2^m).
func NewGF2M(m int) (*GF2M, error) {
	mod := big.NewInt(0)
	switch m {
	case 128:
		mod.SetString(IrreduciblePoly128, 10)
	case 192:
		mod.SetString(IrreduciblePoly192, 10)
	case 256:
		mod.SetString(IrreduciblePoly256, 10)
	default:
		return nil, errors.New("m only supported for 128, 192, or 256")
	}

	return &GF2M{
		Modulus: mod,
	}, nil
}

// Add performs bitwise XOR which is addition in GF(2^m).
func (g *GF2M) Add(a, b *big.Int) *big.Int {
	result := new(big.Int).Xor(a, b)
	return result
}

// Mul performs multiplication in GF(2^m).
// It takes two big.Int values a and b, and returns their product modulo g.Modulus.
func (g *GF2M) Mul(a, b *big.Int) *big.Int {
	result := g.karatsuba(a, b)
	return g.reduce(result)
}

// ExpBySquaringFast computes a^exp in GF(2^m) using the square-and-multiply algorithm.
func (g *GF2M) ExpBySquaringFast(a *big.Int, exp *big.Int) (*big.Int, error) {
	if a.Sign() == 0 {
		return nil, errors.New("cannot raise zero to a power")
	}
	// Start with the multiplicative identity in GF(2^m).
	result := big.NewInt(1)
	base := new(big.Int).Set(a)

	// Convert exp to binary representation for the square-and-multiply algorithm.
	for exp.BitLen() > 0 {
		if exp.Bit(0) == 1 { // If the least significant bit of exp is 1, multiply by the current base.
			result = g.Mul(result, base)
		}
		fmt.Println("alive")

		base = g.Square(base) // Square the base at each step.
		exp.Rsh(exp, 1)       // Right shift exp by 1 (divide by 2).
	}
	fmt.Println("returned")

	return result, nil
}

// Inv computes the multiplicative inverse of a in GF(2^m) using Fermat's Little Theorem.
func (g *GF2M) Inv(a *big.Int) (*big.Int, error) {
	if a.Sign() == 0 {
		return nil, errors.New("zero does not have a multiplicative inverse in GF(2^m)")
	}

	// We want to compute a^(2^m - 2), which is the inverse of a in GF(2^m).
	m := g.Modulus.BitLen() - 1                                                      // Since the modulus represents x^m, its bit length is m+1.
	exp := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(m)), big.NewInt(2)) // Compute 2^m - 2.

	return g.ExpBySquaringFast(a, exp)
}

// Square squares an element in GF(2^m).
func (g *GF2M) Square(a *big.Int) *big.Int {
	// The result starts at 0.
	result := new(big.Int)

	// Iterate over each bit of 'a'.
	for i := 0; i < a.BitLen(); i++ {
		if a.Bit(i) == 1 {
			// For each bit set in 'a', set the bit at position 2*i in the result.
			result = result.SetBit(result, 2*i, 1)
		}
	}

	// Reduce the result to ensure it stays within the field.
	return g.reduce(result)
}

// karatsuba is an internal helper function that performs the Karatsuba algorithm.
func (g *GF2M) karatsuba(a, b *big.Int) *big.Int {
	// Base case for the recursion
	if len(a.Bits()) < 2 || len(b.Bits()) < 2 {
		return g.simpleMultiply(a, b)
	}

	// Calculate the size of the numbers
	m := min(a.BitLen(), b.BitLen())
	m2 := m / 2

	// Split the digit sequences in the middle
	low1 := new(big.Int).Mod(a, new(big.Int).Lsh(big.NewInt(1), uint(m2)))
	high1 := new(big.Int).Rsh(a, uint(m2))
	low2 := new(big.Int).Mod(b, new(big.Int).Lsh(big.NewInt(1), uint(m2)))
	high2 := new(big.Int).Rsh(b, uint(m2))

	// 3 calls made to numbers approximately half the size
	z0 := g.karatsuba(low1, low2)
	z1 := g.karatsuba(new(big.Int).Xor(low1, high1), new(big.Int).Xor(low2, high2))
	z2 := g.karatsuba(high1, high2)

	// Computing the result
	temp := new(big.Int).Xor(z1, z2)
	temp.Xor(temp, z0)
	middle := new(big.Int).Lsh(temp, uint(m2))
	high := new(big.Int).Lsh(z2, uint(2*m2))
	result := new(big.Int).Xor(new(big.Int).Xor(high, middle), z0)

	return g.reduce(result)
}

// reduce reduces a *big.Int modulo the irreducible polynomial of GF2M.
func (g *GF2M) reduce(p *big.Int) *big.Int {
	// Confirm the highest degree term of the modulus is set.
	if g.Modulus.Bit(g.Modulus.BitLen()-1) != 1 {
		panic("modulus is not a monic polynomial")
	}

	mod := new(big.Int).Set(g.Modulus)
	modDegree := mod.BitLen() - 1

	// Create a copy of p to avoid modifying the original value
	pReduced := new(big.Int).Set(p)

	// Perform polynomial long division (simulated with bitwise operations)
	for pReduced.BitLen() >= modDegree {
		// Calculate the shift amount based on the current degree of pReduced.
		shift := uint(pReduced.BitLen() - modDegree)

		// Create a shifted version of the modulus to XOR with pReduced.
		t := new(big.Int).Lsh(mod, shift)

		// XOR pReduced with the shifted modulus t to perform reduction.
		pReduced.Xor(pReduced, t)

		// Ensure that the degree is reduced.
		if pReduced.BitLen() > p.BitLen() {
			panic("degree of polynomial was not reduced - algorithm incorrect or inputs invalid")
		}
	}

	return pReduced
}

// simpleMultiply performs polynomial multiplication without carry,
// which is essentially bit-wise AND operation followed by XOR for addition
func (g *GF2M) simpleMultiply(a, b *big.Int) *big.Int {
	result := new(big.Int)
	for i := 0; i < b.BitLen(); i++ {
		if b.Bit(i) == 1 {
			// Shift 'a' to the left 'i' places, which is equivalent to multiplying by x^i
			temp := new(big.Int).Lsh(a, uint(i))
			// XOR the result with 'temp', simulating polynomial addition
			result.Xor(result, temp)
		}
	}
	return result
}
