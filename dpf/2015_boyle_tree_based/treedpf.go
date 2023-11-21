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

// Key is a concrete implementation of the Key interface for this Tree based DPF.
type Key struct {
	S0, S1 []byte                           // S0, S1 are the initial seeds.
	T0, T1 uint8                            // T0, T1 are the initial control bits.
	CW     map[uint8]map[int]CorrectionWord // CW includes the corrections words of both parties.
	W      *big.Int                         // W hides the partial result that is needed to recalculate the non-zero element.
}

// Serialize serializes the Key into a byte slice for storage or transmission.
func (k *Key) Serialize() ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)

	if err := encoder.Encode(k); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// Deserialize takes a byte slice and populates the Key with the serialized data.
func (k *Key) Deserialize(data []byte) error {
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)

	if err := decoder.Decode(k); err != nil {
		return err
	}

	return nil
}

// TypeID returns the identifier of the Key interface.
func (k *Key) TypeID() dpf.KeyType {
	return dpf.TreeDPFKeyID
}

// EmptyKey creates and returns a new instance of an empty TreeDPF Key.
func EmptyKey() *Key {
	return &Key{
		S0: []byte{},
		S1: []byte{},
		CW: make(map[uint8]map[int]CorrectionWord),
		W:  big.NewInt(0),
	}
}

// TreeDPF is the main structure to initialize, generate, and evaluate the tree-based DPF.
type TreeDPF struct {
	Lambda          int      // Lambda is the security parameter and interpreted in number of bits.
	PrgOutputLength int      // PrgOutputLength sets how many bytes the PRG used in the TreeDPF returns.
	Modulus         *big.Int // Modulus is the mod of the group we are calculating in and is supposed to be prime.
}

// InitFactory initializes a new TreeDPF structure with the given security parameter lambda.
// It returns an error if lambda is not one of the allowed values (128, 192, 256).
func InitFactory(lambda int) (*TreeDPF, error) {
	if lambda != 128 && lambda != 192 && lambda != 256 {
		return nil, errors.New("lambda must be 128, 192, or 256")
	}
	prgOutputLength := 2*(lambda/8) + 1 // Lambda is divided by 8, as the PRG only outputs multiple of bytes

	pow := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(lambda)), nil)
	modulus := dpf.NextPrime(pow)

	return &TreeDPF{
		Lambda:          lambda,
		PrgOutputLength: prgOutputLength,
		Modulus:         modulus,
	}, nil
}

// Gen generates two DPF keys based on a given special point and non-zero element.
// This method follows the Gen algorithm described in the aforementioned paper.
func (d *TreeDPF) Gen(specialPointX *big.Int, nonZeroElementY *big.Int) (dpf.Key, dpf.Key, error) {
	b := nonZeroElementY // This is just syntactic sugar to resemble the formal description of the algorithm.

	// Choosing n as lambda is a practical consideration. N needs to be constant for all evaluations,
	// s.t. the all input values besides the special point will evaluate to zero in Eval.
	// Otherwise, the depth of the tree will vary and the zero requirement of the DPF is not met.
	n := d.Lambda
	if specialPointX.BitLen() > d.Lambda {
		return &Key{}, &Key{}, errors.New("the special point is too large. It must be within [0, 2^Lambda - 1]")

	}

	// Extend the bit length of specialPointX to lambda.
	a, err := dpf.ExtendBigIntToBitLength(specialPointX, d.Lambda)
	if err != nil {
		return &Key{}, &Key{}, err
	}

	seedLength := d.Lambda / 8

	// Initialize Alice and Bob IDs
	const ALICE = 0
	const BOB = 1

	// Initialize nested maps
	parties := []int{ALICE, BOB}
	S := dpf.InitializeMap3LevelsBytes(parties, []int{0, 1}, dpf.MakeRange(0, n))
	T := dpf.InitializeMap3LevelsBool(parties, []int{0, 1}, dpf.MakeRange(0, n))

	// We use `uint8` for the key of the CW because it directly influences the overall key size.
	// Alternatively, we could use a compression function to reduce the key size, but that would introduce
	// additional computational overhead, affecting performance.
	// Note: Go doesn't provide bit-level storage optimization; it operates at the byte level or higher,
	// which is why `uint8` is the most space-efficient choice for storing small integer values.
	CW := initializeMap2LevelsCW([]uint8{ALICE, BOB}, dpf.MakeRange(0, n-1))

	// Create initial seeds (Step 2)
	rootBitA := int(a[0])
	S[ALICE][rootBitA][0] = dpf.RandomSeed(seedLength)
	S[ALICE][1-rootBitA][0] = dpf.RandomSeed(seedLength)
	S[BOB][rootBitA][0] = dpf.RandomSeed(seedLength)
	S[BOB][1-rootBitA][0] = S[ALICE][1-rootBitA][0]

	// Initialize initial control bits (Step 2)
	T[ALICE][rootBitA][0] = dpf.RandomBit()
	T[BOB][rootBitA][0] = !T[ALICE][rootBitA][0]
	T[ALICE][1-rootBitA][0] = dpf.RandomBit()
	T[BOB][1-rootBitA][0] = T[ALICE][1-rootBitA][0]

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
			seed := S[party][int(a[i])][i]
			prgOutput[party] = dpf.PRG(seed, d.PrgOutputLength)

			s[party][0], s[party][1], t[party][0], t[party][1], err = splitPRGOutput(prgOutput[party], d.Lambda)
			if err != nil {
				return &Key{}, &Key{}, err
			}
		}

		nextBitA := int(a[i+1])
		notNextBitA := 1 - nextBitA

		// Step 6 & 7: Choose correction words (cs)
		cs[ALICE][nextBitA] = dpf.RandomSeed(seedLength)
		cs[BOB][nextBitA] = dpf.RandomSeed(seedLength)

		cs[ALICE][notNextBitA] = dpf.RandomSeed(seedLength)
		cs[BOB][notNextBitA] = dpf.XORBytes(s[ALICE][notNextBitA], s[BOB][notNextBitA], cs[ALICE][notNextBitA])

		// Step 8 & 9: Choose correction bits (ct)
		ct[ALICE][nextBitA] = dpf.RandomBit()
		ct[BOB][nextBitA] = !(t[ALICE][nextBitA] != t[BOB][nextBitA] != ct[ALICE][nextBitA]) // != is equivalent to XOR

		ct[ALICE][notNextBitA] = dpf.RandomBit()
		ct[BOB][notNextBitA] = t[ALICE][notNextBitA] != t[BOB][notNextBitA] != ct[ALICE][notNextBitA]

		// Step 10: Store correction words
		for _, party := range parties {
			CW[uint8(party)][i] = CorrectionWord{cs[party][0], cs[party][1], ct[party][0], ct[party][1]}
		}

		// Step 11 & 12: Update S and T for next level
		for _, party := range parties {
			tau := boolToInt(T[party][int(a[i])][i])
			for _, alpha := range []int{0, 1} {
				// Update S
				S[party][alpha][i+1] = dpf.XORBytes(s[party][alpha], cs[tau][alpha])

				// Update T
				T[party][alpha][i+1] = t[party][alpha] != ct[tau][alpha] // != is equivalent to XOR
			}
		}
	}

	// Step 14 to 18: Compute w based on the last level
	finalSeedAlice := S[ALICE][int(a[n-1])][n-1]
	finalSeedBob := S[BOB][int(a[n-1])][n-1]

	partialResultAlice := new(big.Int).SetBytes(dpf.PRG(finalSeedAlice, d.PrgOutputLength))
	partialResultBob := new(big.Int).SetBytes(dpf.PRG(finalSeedBob, d.PrgOutputLength))

	// It is very unlikely that both partial results are equal.
	if partialResultAlice == partialResultBob {
		return &Key{}, &Key{}, errors.New("partial results are equal which is very unlikely")
	}

	sum := new(big.Int).Add(partialResultAlice, partialResultBob)
	sum = sum.Mod(sum, d.Modulus)

	invSum := new(big.Int).ModInverse(sum, d.Modulus)
	if invSum == nil {
		return &Key{}, &Key{}, errors.New("no inverse existing. Check the modulus being used")
	}

	w := new(big.Int).Mul(invSum, b)

	// Step 19: Form the keys k0 and k1
	keys := make(map[int]*Key)
	for _, party := range []int{ALICE, BOB} {
		keys[party] = &Key{
			S0: S[party][0][0],
			S1: S[party][1][0],
			T0: uint8(boolToInt(T[party][0][0])),
			T1: uint8(boolToInt(T[party][1][0])),
			CW: CW,
			W:  w,
		}
	}

	// Step 20: Return the keys
	return keys[ALICE], keys[BOB], nil
}

// Eval evaluates a DPF key at a given point x and returns the result.
// This method follows the Eval algorithm from the paper.
func (d *TreeDPF) Eval(key dpf.Key, x *big.Int) (*big.Int, error) {
	// Use a type assertion to convert dpf.Key to the concrete key type for this dpf implementation.
	tkey, ok := key.(*Key)
	if !ok {
		return nil, errors.New("the given key is not a tree-based DPF key")
	}

	n := d.Lambda

	if x.BitLen() > d.Lambda {
		return nil, errors.New("the given point is too large. It must be within [0, 2^Lambda - 1]")
	}

	a, err := dpf.ExtendBigIntToBitLength(x, d.Lambda)
	if err != nil {
		return nil, err
	}

	// Step 4 & 5: Initialize S and T based on fist bit of x (-> which edge to take to get the initial seed/cbit)
	var S []byte
	var T uint8
	if a[0] == 0 {
		S = tkey.S0
		T = tkey.T0
	} else {
		S = tkey.S1
		T = tkey.T1
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
		if a[i] == 0 {
			S = dpf.XORBytes(s0, tkey.CW[T][i-1].Cs0)
			T = uint8(boolToInt(t0 != tkey.CW[T][i-1].Ct0)) // != is equivalent to XOR

		} else {
			S = dpf.XORBytes(s1, tkey.CW[T][i-1].Cs1)
			T = uint8(boolToInt(t1 != tkey.CW[T][i-1].Ct1)) // != is equivalent to XOR
		}
	}

	// Step 12: Compute the final output
	partialResult := new(big.Int).SetBytes(dpf.PRG(S, d.PrgOutputLength))
	partialResultW := new(big.Int).Mul(tkey.W, partialResult)
	partialResult.Mod(partialResultW, d.Modulus)
	return partialResult, nil
}

// CombineResults takes the results from two DPF key evaluations for a certain point and combines them.
// When both y1 and y2 are equal, the point used for evaluation was not the special point and the combined result
// is 0, according to the definition of a Point Function.
func (d *TreeDPF) CombineResults(y1 *big.Int, y2 *big.Int) *big.Int {
	if y1.Cmp(y2) == 0 {
		return big.NewInt(0)
	}
	sum := new(big.Int).Add(y1, y2)
	sum.Mod(sum, d.Modulus)
	return sum
}

func (d *TreeDPF) FullEval(key dpf.Key) ([]*big.Int, error) {
	return nil, errors.New("not implemented")
}

func (d *TreeDPF) FullEvalFast(key dpf.Key) ([]*big.Int, error) {
	return nil, errors.New("not implemented")
}

// CorrectionWord holds the correction words and bits for the DPF key.
type CorrectionWord struct {
	Cs0, Cs1 []byte
	Ct0, Ct1 bool
}

// initializeMap2LevelsCW initializes a 2-level map with CorrectionWord values.
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

// splitPRGOutput splits the output of the PRG into two seeds and two control bits.
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

// initializeSubMaps initializes maps for s, cs, t, and ct values used in the Gen method.
func initializeSubMaps() (map[int][]byte, map[int][]byte, map[int]bool, map[int]bool) {
	return make(map[int][]byte), make(map[int][]byte), make(map[int]bool), make(map[int]bool)
}

// boolToInt converts a boolean value to its integer representation.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
