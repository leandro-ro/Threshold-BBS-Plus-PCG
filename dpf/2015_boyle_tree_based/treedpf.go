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
	"math/big"
	"pcg-master-thesis/dpf"
)

// Key is a concrete implementation of the Key interface for our specific DPF
type Key struct {
	S0, S1        []byte                           // S0, S1 are the initial seeds.
	T0, T1        uint8                            // T0, T1 are the initial control bits.
	CW            map[uint8]map[int]CorrectionWord // CW includes the corrections words of both parties.
	W             *big.Int                         // W hides the partial result that is needed to recalculate the non-zero element.
	CompensateSum uint8                            // CompensateSum indicates if the partial result needs to be incremented by 1.
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
	Lambda          int      // Lambda is the security parameter and interpreted in number of bits.
	M               int      // M sets the bit length of the non-zero element. For this implementation it is equal to lambda.
	Modulus         *big.Int // Modulus is used to do calculations inside a finite field of 2^m.
	PrgOutputLength int      // PrgOutputLength sets how many bytes the PRG used in the TreeDPF returns.
}

func GetTreeDPF(lambda int) (*TreeDPF, error) {
	if lambda != 128 && lambda != 192 && lambda != 256 {
		return nil, errors.New("lambda must be 128, 192, or 256")
	}

	m := lambda
	modulus := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m)), nil)
	prgOutputLength := 2*(lambda/8) + 1 // Lambda is divided by 8, as the PRG only outputs multiple of bytes

	return &TreeDPF{
		Lambda:          lambda,
		M:               m,
		Modulus:         modulus,
		PrgOutputLength: prgOutputLength,
	}, nil
}

func (d *TreeDPF) Gen(specialPointX *big.Int, nonZeroElementY *big.Int) (Key, Key, error) {
	// Calculating the bit length of specialPointX
	a := specialPointX   // This is just syntactic sugar to resemble the formal description of the algorithm.
	b := nonZeroElementY // This is just syntactic sugar to resemble the formal description of the algorithm.
	n := a.BitLen()
	seedLength := d.Lambda / 8

	// Initialize Alice and Bob IDs
	const ALICE = 0
	const BOB = 1

	// Initialize nested maps
	parties := []int{ALICE, BOB}
	S := initializeMap3LevelsBytes(parties, []int{0, 1}, makeRange(0, n))
	T := initializeMap3LevelsBool(parties, []int{0, 1}, makeRange(0, n))

	// We use `uint8` for the key of the CW because it directly influences the overall key size.
	// Alternatively, we could use a compression function to reduce the key size, but that would introduce
	// additional computational overhead, affecting performance.
	// Note: Go doesn't provide bit-level storage optimization; it operates at the byte level or higher,
	// which is why `uint8` is the most space-efficient choice for storing small integer values.
	CW := initializeMap2LevelsCW([]uint8{ALICE, BOB}, makeRange(0, n-1))

	// Create initial seeds (Step 2)
	S[ALICE][0][0] = dpf.RandomSeed(seedLength)
	S[ALICE][1][0] = dpf.RandomSeed(seedLength)
	S[BOB][0][0] = dpf.RandomSeed(seedLength)
	S[BOB][1][0] = S[ALICE][1][0]

	// Initialize initial control bits (Step 2)
	T[ALICE][0][0] = dpf.RandomBit()
	T[ALICE][1][0] = dpf.RandomBit()
	T[BOB][0][0] = !T[ALICE][0][0]
	T[BOB][1][0] = T[ALICE][1][0]

	// Loop to populate S, T, and CW (Steps 4 to 13)
	for i := 0; i < n-1; i++ {
		// Step 4: Initialize variables for this iteration
		prgOutput := make(map[int][]byte)
		s := make(map[int]map[int][]byte)
		cs := make(map[int]map[int][]byte)
		t := make(map[int]map[int]bool)
		ct := make(map[int]map[int]bool)

		var err error
		for _, party := range parties {
			s[party], cs[party], t[party], ct[party] = initializeSubMaps()

			// Step 5: Use PRG to expand current seed
			seed := S[party][int(a.Bit(i))][i]
			prgOutput[party] = dpf.PRG(seed, d.PrgOutputLength)

			s[party][0], s[party][1], t[party][0], t[party][1], err = splitPRGOutput(prgOutput[party], d.Lambda)
			if err != nil {
				return Key{}, Key{}, err
			}
		}

		nextA := int(a.Bit(i + 1))
		notNextA := 1 - nextA

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
			CW[uint8(party)][i] = CorrectionWord{cs[party][0], cs[party][1], ct[party][0], ct[party][1]}
		}

		// Step 11 & 12: Update S and T for next level
		for _, party := range parties {
			tau := boolToInt(T[party][int(a.Bit(i))][i])
			for _, alpha := range []int{0, 1} {
				// Update S
				S[party][alpha][i+1] = dpf.XORBytes(s[party][alpha], cs[tau][alpha])

				// Update T
				T[party][alpha][i+1] = t[party][alpha] != ct[tau][alpha] // != is equivalent to XOR
			}
		}
	}

	// Step 14 to 18: Compute w based on the last level
	finalSeedAlice := S[ALICE][int(a.Bit(n-1))][n-1]
	finalSeedBob := S[BOB][int(a.Bit(n-1))][n-1]

	partialResultAlice := new(big.Int).SetBytes(dpf.PRG(finalSeedAlice, d.PrgOutputLength))
	partialResultAlice.Mod(partialResultAlice, d.Modulus)

	partialResultBob := new(big.Int).SetBytes(dpf.PRG(finalSeedBob, d.PrgOutputLength))
	partialResultBob.Mod(partialResultBob, d.Modulus)

	sumTerm := new(big.Int).Add(partialResultAlice, partialResultBob)
	sumTerm.Mod(sumTerm, d.Modulus)

	// Deviation from Formal Definition for Invertibility:
	// ---------------------------------------------------
	// In the standard protocol, we sum the partial results from both parties to get 'sum_term',
	// and then find its modular inverse modulo 2^m. However, there's no guarantee that 'sum_term'
	// will be coprime to 2^m, which is essential for finding its modular inverse.
	//
	// To overcome this, we introduce an adjustment to ensure that 'sum_term' is odd. Since 2^m is a power of 2,
	// an odd 'sum_term' is guaranteed to be coprime to 2^m, thereby ensuring its invertibility.
	//
	// TODO: Check for security problems
	//
	// Flag for Adjustment:
	// ---------------------
	// We use a flag named 'ensureOdd' to indicate the need for this adjustment. If 'sum_term' happens to be even,
	// we increment it by 1 to make it odd and set the ENSURE_ODD flag to True.
	//
	// This flag will be part of the distributed key and will be used to signal one of the parties (chosen at random)
	// to increment their partial result by 1, thereby compensating for this adjustment.
	//
	// This ensures that 'sum_term' is always odd (and hence, coprime to 2^m), allowing us to find its modular inverse.
	ensureOdd := false
	if sumTerm.Bit(0) == 0 {
		sumTerm.Add(sumTerm, big.NewInt(1))
		ensureOdd = true
	}

	invTerm := new(big.Int).ModInverse(sumTerm, d.Modulus)
	if invTerm == nil {
		return Key{}, Key{}, errors.New("failed to properly calculate w")
	}
	w := new(big.Int).Mul(invTerm, b)
	w.Mod(w, d.Modulus)

	// Randomly decide which key to adjust if sumTerm was made odd
	sumCompensationFlags := [2]int{0, 0}
	if ensureOdd {
		sumCompensationFlags[boolToInt(dpf.RandomBit())] = 1
	}

	// Step 19: Form the keys k0 and k1
	keys := make(map[int]Key)
	for _, party := range []int{ALICE, BOB} {
		keys[party] = Key{
			S0:            S[party][0][0],
			S1:            S[party][1][0],
			T0:            uint8(boolToInt(T[party][0][0])),
			T1:            uint8(boolToInt(T[party][1][0])),
			CW:            CW,
			W:             w,
			CompensateSum: uint8(sumCompensationFlags[party]),
		}
	}

	// Step 20: Return the keys
	return keys[ALICE], keys[BOB], nil
}

func (d *TreeDPF) Eval(key Key, x *big.Int) (*big.Int, error) {
	n := x.BitLen()
	result := big.NewInt(0)
	a := x

	// Step 4 & 5: Initialize S and T based on fist bit of x (-> which edge to take to get the initial seed/cbit)
	var S []byte
	var T uint8
	if a.Bit(0) == 0 {
		S = key.S0
		T = key.T0
	} else {
		S = key.S1
		T = key.T1
	}

	// Step 6 to 11: Iterate through levels to update S and T
	for i := 1; i < n; i++ {
		// Step 7: Use PRG to expand current seed S
		prgOutput := dpf.PRG(S, d.PrgOutputLength)
		s0, s1, t0, t1, err := splitPRGOutput(prgOutput, d.Lambda)
		if err != nil {
			return nil, err
		}

		// Step 8 to 10: Update S and T based on the next bit and correction word
		if x.Bit(i) == 0 {
			S = dpf.XORBytes(s0, key.CW[T][i-1].Cs0)
			T = uint8(boolToInt(t0 != key.CW[T][i-1].Ct0)) // != is equivalent to XOR
		} else {
			S = dpf.XORBytes(s1, key.CW[T][i-1].Cs1)
			T = uint8(boolToInt(t1 != key.CW[T][i-1].Ct1)) // != is equivalent to XOR
		}
	}

	// Step 23: Update the result
	partialResult := new(big.Int).SetBytes(dpf.PRG(S, d.PrgOutputLength))
	partialResult.Mod(partialResult, d.Modulus)
	result.Add(result, partialResult)
	result.Mod(result, d.Modulus)

	// Step 24: Finalize result
	if key.CompensateSum != 0 {
		result.Add(result, big.NewInt(1))
		result.Mod(result, d.Modulus)
	}
	result.Mul(result, key.W)
	result.Mod(result, d.Modulus)

	return result, nil
}

func initializeMap3LevelsBytes(keys1, keys2, keys3 []int) map[int]map[int]map[int][]byte {
	m := make(map[int]map[int]map[int][]byte)
	for _, k1 := range keys1 {
		m[k1] = make(map[int]map[int][]byte)
		for _, k2 := range keys2 {
			m[k1][k2] = make(map[int][]byte)
			for _, k3 := range keys3 {
				m[k1][k2][k3] = nil
			}
		}
	}
	return m
}

func initializeMap3LevelsBool(keys1, keys2, keys3 []int) map[int]map[int]map[int]bool {
	m := make(map[int]map[int]map[int]bool)
	for _, k1 := range keys1 {
		m[k1] = make(map[int]map[int]bool)
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

func initializeMap2LevelsCW(keys1 []uint8, keys2 []int) map[uint8]map[int]CorrectionWord {
	m := make(map[uint8]map[int]CorrectionWord)
	for _, k1 := range keys1 {
		m[k1] = make(map[int]CorrectionWord)
		for _, k2 := range keys2 {
			m[k1][k2] = CorrectionWord{}
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

func splitPRGOutput(prgOutput []byte, lambda int) ([]byte, []byte, bool, bool, error) {
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

func initializeSubMaps() (map[int][]byte, map[int][]byte, map[int]bool, map[int]bool) {
	return make(map[int][]byte), make(map[int][]byte), make(map[int]bool), make(map[int]bool)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
