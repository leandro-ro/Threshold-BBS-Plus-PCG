// Package treedpf provides a tree-based Distributed Point Function implementation.
// It is based on Algorithm 1 (Gen) & 2 (Eval) from "Function Secret Sharing"
// by Elette Boyle, Niv Gilboa, and Yuval Ishai, published in EUROCRYPT 2015.
// Link: https://link.springer.com/content/pdf/10.1007/978-3-662-46803-6_12.pdf
//
// Author: Leandro Rometsch
// Date: October 2023
// Affiliation: Technical University of Darmstadt, Chair of Applied Cryptography
package treedpf

import (
	"bytes"
	"encoding/gob"
	"errors"
	"math"
	"math/big"
	"pcg-master-thesis/dpf"
)

// Key is a concrete implementation of the Key interface for our specific DPF
type Key struct {
	S0, S1        []byte            // S0, S1 are the initial seeds.
	T0, T1        int               // T0, T1 are the initial control bits.
	CW            map[int][4][]byte // CW includes the corrections words of both parties.
	W             *big.Int          // W hides the partial result that is needed to recalculate the non-zero element.
	CompensateSum int               // CompensateSum indicates if the partial result needs to be incremented by 1.
}

// Serialize serializes the TKey
func (k *Key) Serialize() ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)

	if err := encoder.Encode(k); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// Deserialize deserializes the TKey
func (k *Key) Deserialize(data []byte) error {
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)

	if err := decoder.Decode(k); err != nil {
		return err
	}

	return nil
}

type TreeDPF struct {
	Lambda          int // Lambda is the security parameter and interpreted in # bits.
	M               int // M sets the bit length of the non-zero element. For this implementation it is equal to lambda.
	Modulus         int // Modulus is used to do calculations inside a finite field of 2^m.
	PrgOutputLength int // PrgOutputLength sets how many bytes the PRG used in the TreeDPF returns.
}

func GetTreeDPF(lambda int) (*TreeDPF, error) {
	if lambda != 128 && lambda != 192 && lambda != 256 {
		return nil, errors.New("lambda must be 128, 192, or 256")
	}

	m := lambda
	modulus := int(math.Pow(2.0, float64(m)))
	prgOutputLength := 2*(lambda/8) + 1 // Lambda is divided by 8, as the PRG only outputs multiple of bytes

	return &TreeDPF{
		Lambda:          lambda,
		M:               m,
		Modulus:         modulus,
		PrgOutputLength: prgOutputLength,
	}, nil
}

func (d *TreeDPF) Gen(specialPointX *big.Int, nonZeroElementY *big.Int) (TreeDPF, Key, error) {
	// Calculating the bit length of specialPointX
	a := specialPointX   // This is just syntactic sugar to resemble the formal description of the algorithm.
	b := nonZeroElementY // This is just syntactic sugar to resemble the formal description of the algorithm.
	n := a.BitLen()

	// Initialize Alice and Bob IDs
	const ALICE = uint8(0) // We use uint8 for memory efficiency.
	const BOB = uint8(1)

	// Initialize nested maps
	parties := []uint8{ALICE, BOB}
	S := initializeMap3LevelsBytes(parties, []uint8{0, 1}, makeRange(0, n))
	T := initializeMap3LevelsBool(parties, []uint8{0, 1}, makeRange(0, n)) // We use bool for memory efficiency.
	CW := initializeMap2LevelsBytes(parties, makeRange(0, n-1))

	// Create initial seeds (Step 2)
	S[ALICE][0][0] = dpf.RandomSeed(d.Lambda)
	S[ALICE][1][0] = dpf.RandomSeed(d.Lambda)
	S[BOB][0][0] = dpf.RandomSeed(d.Lambda)
	S[BOB][1][0] = S[ALICE][1][0]

	// Initialize initial control bits (Step 2)
	T[ALICE][0][0] = dpf.RandomBit()
	T[ALICE][1][0] = dpf.RandomBit()
	T[BOB][0][0] = !T[ALICE][0][0]
	T[BOB][1][0] = T[ALICE][1][0]

	// Loop to populate S, T, and CW (Steps 4 to 13)
	for i := 0; i < n-1; i++ {
		// Step 4: Initialize variables for this iteration
		prgOutput := make(map[uint8][]byte)
		s := make(map[uint8]map[uint8][]byte)
		cs := make(map[uint8]map[uint8][]byte)
		t := make(map[uint8]map[uint8]bool)
		ct := make(map[uint8]map[uint8]bool)

		var err error
		for _, party := range parties {
			// Step 5: Use PRG to expand current seed
			seed := S[party][uint8(a.Bit(i))][i]
			prgOutput[party] = dpf.PRG(seed, d.PrgOutputLength)

			s[party][0], s[party][1], t[party][0], t[party][1], err = SplitPRGOutput(prgOutput[party], d.Lambda)
			if err != nil {
				return TreeDPF{}, Key{}, err
			}
		}

		nextA := uint8(a.Bit(i + 1))
		notNextA := 1 - nextA

		seedLength := d.Lambda / 8
		// Step 6 & 7: Choose correction words (cs)
		cs[ALICE][nextA] = dpf.RandomSeed(seedLength)
		cs[BOB][nextA] = dpf.RandomSeed(seedLength)

		cs[ALICE][notNextA] = dpf.RandomSeed(seedLength)
		cs[BOB][notNextA] = dpf.XORBytes(s[ALICE][notNextA], s[BOB][notNextA], cs[ALICE][notNextA])

		// Step 8 & 9: Choose correction bits (ct)
		ct[ALICE][nextA] = dpf.RandomBit()
		ct[BOB][nextA] = !(t[ALICE][nextA] != t[BOB][nextA] != ct[ALICE][nextA]) // != is equivalent to XOR

		ct[ALICE][notNextA] = dpf.RandomBit()
		ct[BOB][notNextA] = t[ALICE][notNextA] != t[BOB][notNextA] != ct[ALICE][notNextA]

		// Step 10: Store correction words
		for _, party := range parties {
			CW[party][i] = [4][]byte{cs[party][0], cs[party][1], {byte(ct[party][0])}, []byte{byte(ct[party][1])}}
		}

		// Step 11 & 12: Update S and T for next level
		for _, party := range parties {
			tau := T[party][uint8(a.Bit(i))][i]
			for _, alpha := range []uint8{0, 1} {
				// Update S
				S[party][alpha][i+1] = dpf.XORBytes(s[party][alpha], cs[tau][alpha]) // Assume XORBytes function exists

				// Update T
				T[party][alpha][i+1] = t[party][alpha] != ct[tau][alpha]
			}
		}

	}

	return nil, nil, nil
}

func (d *TreeDPF) Eval(key Key, x *big.Int) (*big.Int, error) {
	// implementation
	return nil, nil
}

func initializeMap3LevelsBytes(keys1, keys2 []uint8, keys3 []int) map[uint8]map[uint8]map[int][]byte {
	m := make(map[uint8]map[uint8]map[int][]byte)
	for _, k1 := range keys1 {
		m[k1] = make(map[uint8]map[int][]byte)
		for _, k2 := range keys2 {
			m[k1][k2] = make(map[int][]byte)
			for _, k3 := range keys3 {
				m[k1][k2][k3] = nil
			}
		}
	}
	return m
}

func initializeMap3LevelsBool(keys1, keys2 []uint8, keys3 []int) map[uint8]map[uint8]map[int]bool {
	m := make(map[uint8]map[uint8]map[int]bool)
	for _, k1 := range keys1 {
		m[k1] = make(map[uint8]map[int]bool)
		for _, k2 := range keys2 {
			m[k1][k2] = make(map[int]bool)
			for _, k3 := range keys3 {
				m[k1][k2][k3] = false
			}
		}
	}
	return m
}

type CorrectionWord struct {
	Cs0, Cs1 []byte
	Ct0, Ct1 bool
}

func initializeMap2LevelsStruct(keys1 []uint8, keys2 []int) map[uint8]map[int]CorrectionWords {
	m := make(map[uint8]map[int]CorrectionWords)
	for _, k1 := range keys1 {
		m[k1] = make(map[int]CorrectionWords)
		for _, k2 := range keys2 {
			m[k1][k2] = CorrectionWords{}
		}
	}
	return m
}

func makeRange(min, max int) []int {
	a := make([]int, max-min)
	for i := range a {
		a[i] = min + i
	}
	return a
}

func SplitPRGOutput(prgOutput []byte, lambda int) ([]byte, []byte, bool, bool, error) {
	lambdaBytes := lambda / 8
	if len(prgOutput) < 2*lambdaBytes+1 {
		return nil, nil, false, false, errors.New("insufficient length of PRG output")
	}

	s0 := prgOutput[:lambdaBytes]
	s1 := prgOutput[lambdaBytes : 2*lambdaBytes]
	t0 := (prgOutput[2*lambdaBytes] & 1) != 0 // Interpret as bool for storage efficiency
	t1 := ((prgOutput[2*lambdaBytes] >> 1) & 1) != 0

	return s0, s1, t0, t1, nil
}
