// Package optreedpf provides an optimized tree-based Distributed Point Function implementation.
// It is based on Figure 1 (Gen, Eval) & 3 (Convert) from "Function Secret Sharing: Improvements and Extensions"
// by Elette Boyle, Niv Gilboa, and Yuval Ishai, originally published at CCS '16.
// For this implementation the revised version of the paper from 2018 was used.
// Link: https://eprint.iacr.org/2018/707.pdf
//
// Author: Leandro Rometsch
// Date: November 2023
// Affiliation: Technical University of Darmstadt, Chair of Applied Cryptography
package optreedpf

import (
	"bytes"
	"encoding/gob"
	"errors"
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"pcg-master-thesis/dpf"
)

// Key is a concrete implementation of the Key interface for this Tree based DPF.
type Key struct {
	ID uint8                  // ID identifies the party the key belongs to.
	S  []byte                 // S is the initial seed.
	CW map[int]CorrectionWord // CW includes the corrections words.
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

// TypeID returns the identifier of the Key.
func (k *Key) TypeID() dpf.KeyType {
	return dpf.OpTreeDPFKeyID
}

// EmptyKey creates and returns a new instance of an empty Key.
func EmptyKey() *Key {
	return &Key{
		ID: 2, // ID is set to != 0 and != 1 to indicate an empty key
		S:  []byte{},
		CW: make(map[int]CorrectionWord),
	}
}

// CorrectionWord represents a correction word for a specific level in the DPF Tree.
type CorrectionWord struct {
	S      []byte
	Tl, Tr bool
}

type OpTreeDPF struct {
	Lambda          int      // Lambda is the security parameter and interpreted in number of bits.
	prgOutputLength int      // prgOutputLength sets how many bytes the PRG used in the TreeDPF returns.
	DomainBitLength int      // DomainBitLength is the bit length of the DPFs input domain.
	AlphaMax        *big.Int // AlphaMax is the maximum value of the special point. It is equal to 2^DomainBitLength - 1.
	BetaMax         *big.Int // BetaMax is the maximum value of the non-zero element.
}

// InitFactory initializes a new OpTreeDPF structure.
// lambda is the security parameter and interpreted in number of bits.
// inputDomain describes the bit length of input domain of the DPF. It limits the non-zero element to be within [0, 2^n - 1].
// The constructor returns an error if lambda is not one of (128, 192, 256).
func InitFactory(lambda int, inputDomain int) (*OpTreeDPF, error) {
	if lambda != 128 && lambda != 192 && lambda != 256 {
		return nil, errors.New("lambda must be 128, 192, or 256")

	}

	prgOutputLength := 2 * (lambda/8 + 1)

	alphaMax := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(inputDomain)), nil)
	alphaMax.Sub(alphaMax, big.NewInt(1))
	betaMax, _ := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16) // This is the group order of the BLS12-381 curve

	return &OpTreeDPF{
		Lambda:          lambda,
		prgOutputLength: prgOutputLength,
		DomainBitLength: inputDomain,
		AlphaMax:        alphaMax,
		BetaMax:         betaMax,
	}, nil
}

// Gen generates two DPF keys based on a given special point and non-zero element.
// This method follows the Gen algorithm described in the aforementioned paper.
func (d *OpTreeDPF) Gen(specialPointX *big.Int, nonZeroElementY *big.Int) (dpf.Key, dpf.Key, error) {
	n := d.DomainBitLength // Syntactic sugar to resemble the formal description of the algorithm.
	if specialPointX.Cmp(d.AlphaMax) == 1 {
		return &Key{}, &Key{}, errors.New("the special point is too large. It must be within the Domain of the DPF")

	}

	beta := nonZeroElementY // Syntactic sugar to resemble the formal description of the algorithm.
	if beta.Cmp(d.BetaMax) == 1 {
		return &Key{}, &Key{}, errors.New("the non-zero element is too large for the group order used")
	}

	// Extend the bit length of specialPointX to DomainBitLength.
	alpha, err := dpf.ExtendBigIntToBitLength(specialPointX, d.DomainBitLength)
	if err != nil {
		return &Key{}, &Key{}, err
	}

	seedLength := d.Lambda / 8

	// Initialize Alice and Bob IDs
	const ALICE = 0
	const BOB = 1

	// Initialize nested maps
	parties := []int{ALICE, BOB}
	CW := make(map[int]CorrectionWord)
	s := dpf.InitializeMap2LevelsBytes(parties, dpf.MakeRange(0, n))
	t := dpf.InitializeMap2LevelsBool(parties, dpf.MakeRange(0, n))

	// Step 2: Initialize with random seeds
	s[ALICE][0] = dpf.RandomSeed(seedLength)
	s[BOB][0] = dpf.RandomSeed(seedLength)

	// Step 3: Set t0 and t1
	t[ALICE][0] = false // = 0
	t[BOB][0] = true    // = 1

	// Step 4: Create Tree
	const L = 0
	const R = 1
	sTmp := dpf.InitializeMap2LevelsBytes(parties, []int{L, R})
	tTmp := dpf.InitializeMap2LevelsBool(parties, []int{L, R})
	for i := 1; i <= n; i++ {
		// Step 5: Call PRG
		for party := range parties {
			prgOutput := dpf.PRG(s[party][i-1], d.prgOutputLength)
			sTmp[party][L], tTmp[party][L], sTmp[party][R], tTmp[party][R], err = splitPRGOutput(prgOutput, d.Lambda)
			if err != nil {
				return nil, nil, err
			}
		}

		// Step 6-11: Choose correction words
		alphaBool := alpha[i-1] != 0 // Interpret alpha[i-1] as boolean
		keep, loose := L, R
		if alphaBool {
			keep = R
			loose = L
		}

		sCW := dpf.XORBytes(sTmp[ALICE][loose], sTmp[BOB][loose])
		tCW := make([]bool, 2)
		tCW[L] = tTmp[ALICE][L] != tTmp[BOB][L] != alphaBool != true // != is eq to XOR
		tCW[R] = tTmp[ALICE][R] != tTmp[BOB][R] != alphaBool

		CW[i-1] = CorrectionWord{
			S:  sCW,
			Tl: tCW[L],
			Tr: tCW[R],
		}

		// Step 12-13: Set next S and t
		for party := range parties {
			// t_b^(i-1) is the previous control bit
			tPrevBit := t[party][i-1]

			// Update seeds and control bits
			if tPrevBit {
				// If tPrevBit is true, XOR with correction word
				s[party][i] = dpf.XORBytes(sTmp[party][keep], sCW)
				t[party][i] = tTmp[party][keep] != tCW[keep] // != is eq to XOR
			} else {
				// If tPrevBit is false, use the value from the keep branch
				s[party][i] = sTmp[party][keep]
				t[party][i] = tTmp[party][keep]
			}
		}
	}

	// Step 15: Compute final "Correction Word" and hide beta in it.
	finalSeedAlice := new(big.Int).SetBytes(s[ALICE][n])
	finalSeedBob := new(big.Int).SetBytes(s[BOB][n])
	res, err := d.genGroupCalc(finalSeedAlice, finalSeedBob, beta, t[BOB][n])

	CW[n] = CorrectionWord{
		S:  res,
		Tl: false, // Value of Tl and Tr doesn't matter for the last CW
		Tr: false,
	}

	// Step 16: Create DPF keys
	keyAlice := Key{
		ID: ALICE,
		S:  s[ALICE][0],
		CW: CW,
	}
	keyBob := Key{
		ID: BOB,
		S:  s[BOB][0],
		CW: CW,
	}
	return &keyAlice, &keyBob, nil
}

// Eval evaluates a DPF key at a given point x and returns the result.
// This method follows the Eval algorithm from the paper.
func (d *OpTreeDPF) Eval(key dpf.Key, x *big.Int) (*big.Int, error) {
	// Use a type assertion to convert dpf.Key to the concrete key type for this dpf implementation.
	tkey, ok := key.(*Key)
	if !ok {
		return nil, errors.New("the given key is not a tree-based DPF key")
	}
	if tkey.ID > 1 {
		return nil, errors.New("the given key is invalid as its ID can only be 0 or 1")
	}

	n := d.DomainBitLength
	if x.Cmp(d.AlphaMax) == 1 {
		return nil, errors.New("the given point is too large. It must be within [0, 2^Lambda - 1]")
	}

	a, err := dpf.ExtendBigIntToBitLength(x, d.DomainBitLength)
	if err != nil {
		return nil, err
	}

	// Step: 1: Parse key
	s := tkey.S
	t := tkey.ID != 0 // Interpret ID as boolean
	for i := 1; i <= n; i++ {
		// Step 3: Parse correction word
		scw := tkey.CW[i-1].S
		tcwl := tkey.CW[i-1].Tl
		tcwr := tkey.CW[i-1].Tr

		// Step 4: Calculate tau
		tau := dpf.PRG(s, d.prgOutputLength)
		if t {
			appendedSlices := append(scw, boolToByteSlice(tcwl)...)
			appendedSlices = append(appendedSlices, scw...)
			appendedSlices = append(appendedSlices, boolToByteSlice(tcwr)...)
			if len(appendedSlices) != len(tau) {
				return nil, errors.New("length of appended slices does not match length of tau")
			}
			tau = dpf.XORBytes(tau, appendedSlices)
		}

		// Step 5: Parse tau as PRG output
		sl, tl, sr, tr, err := splitPRGOutput(tau, d.Lambda)
		if err != nil {
			return nil, err
		}

		// Step 6-7: Set next S and t
		if a[i-1] == 0 {
			s = sl
			t = tl
		} else {
			s = sr
			t = tr
		}
	}
	// Step 10: Calculate partial result
	finalSeed := new(big.Int).SetBytes(s)
	partialResult, err := d.evalGroupCalc(finalSeed, tkey.CW[n].S, tkey.ID, t)
	if err != nil {
		return nil, err
	}
	return partialResult, nil
}

// CombineResults combines the results of two partial evaluations into a single result.
// It performs simple finite field addition.
func (d *OpTreeDPF) CombineResults(y1 *big.Int, y2 *big.Int) *big.Int {
	y1C := bls12381.NewFr().FromBytes(y1.Bytes())
	y2C := bls12381.NewFr().FromBytes(y2.Bytes())

	res := bls12381.NewFr()
	res.Add(y1C, y2C)
	return res.ToBig()
}

// CombineMultipleResults combines the results of two partial evaluations into a single result.
// It performs finite field addition for each pair of elements in y1 and y2.
// Returns an error if the lengths of y1 and y2 do not match.
func (d *OpTreeDPF) CombineMultipleResults(y1, y2 []*big.Int) ([]*big.Int, error) {
	if len(y1) != len(y2) {
		return nil, errors.New("y1 and y2 must have the same length")
	}

	result := make([]*big.Int, len(y1))
	for i := range y1 {
		result[i] = d.CombineResults(y1[i], y2[i])
	}

	return result, nil
}

// FullEval evaluates a DPF key at all points in the domain and returns the results of each point in an array.
func (d *OpTreeDPF) FullEval(key dpf.Key) ([]*big.Int, error) {
	// Use a type assertion to convert dpf.Key to the concrete key type for this dpf implementation.
	tkey, ok := key.(*Key)
	if !ok {
		return nil, errors.New("the given key is not a tree-based DPF key")
	}
	if tkey.ID > 1 {
		return nil, errors.New("the given key is invalid as its ID can only be 0 or 1")
	}

	initT := tkey.ID != 0 // Interpret ID as boolean
	initS := tkey.S

	res, err := d.traverse(initS, initT, tkey.CW, d.DomainBitLength, tkey.ID)

	if err != nil {
		return nil, err
	}
	return res, nil
}

// FullEvalFast evaluates a DPF key at all points in the domain and returns the results of each point in an array.
// It uses parallelization to speed up the evaluation.
func (d *OpTreeDPF) FullEvalFast(key dpf.Key) ([]*big.Int, error) {
	// Use a type assertion to convert dpf.Key to the concrete key type for this dpf implementation.
	tkey, ok := key.(*Key)
	if !ok {
		return nil, errors.New("the given key is not a tree-based DPF key")
	}
	if tkey.ID > 1 {
		return nil, errors.New("the given key is invalid as its ID can only be 0 or 1")
	}

	initT := tkey.ID != 0 // Interpret ID as boolean
	initS := tkey.S

	res, err := d.traverseParallel(initS, initT, tkey.CW, d.DomainBitLength, tkey.ID)

	if err != nil {
		return nil, err
	}
	return res, nil
}

// traverse traverses the tree and returns the partial results.
func (d *OpTreeDPF) traverse(s []byte, t bool, CW map[int]CorrectionWord, i int, partyID uint8) ([]*big.Int, error) {
	if i > 0 {
		pos := d.DomainBitLength - i
		// Parse correction word
		scw := CW[pos].S
		tcwl := CW[pos].Tl
		tcwr := CW[pos].Tr

		// Calculate tau
		tau := dpf.PRG(s, d.prgOutputLength)
		if t {
			appendedSlices := append(scw, boolToByteSlice(tcwl)...)
			appendedSlices = append(appendedSlices, scw...)
			appendedSlices = append(appendedSlices, boolToByteSlice(tcwr)...)
			if len(appendedSlices) != len(tau) {
				return nil, errors.New("length of appended slices does not match length of tau")
			}
			tau = dpf.XORBytes(tau, appendedSlices)
		}

		// Step 5: Parse tau as PRG output
		sl, tl, sr, tr, err := splitPRGOutput(tau, d.Lambda)
		if err != nil {
			return nil, err
		}

		left, err := d.traverse(sl, tl, CW, i-1, partyID)
		if err != nil {
			return nil, err
		}
		right, err := d.traverse(sr, tr, CW, i-1, partyID)
		if err != nil {
			return nil, err
		}
		return append(left, right...), nil

	} else { // i = 0
		// Calculate partial result
		finalSeed := new(big.Int).SetBytes(s)
		partialResult, err := d.evalGroupCalc(finalSeed, CW[d.DomainBitLength].S, partyID, t)
		if err != nil {
			return nil, err
		}
		return []*big.Int{partialResult}, nil
	}
}

// traverseParallel traverses the tree and returns the partial results.
// On each few levels, it spawns a new thread for the left and right branch.
func (d *OpTreeDPF) traverseParallel(s []byte, t bool, CW map[int]CorrectionWord, i int, partyID uint8) ([]*big.Int, error) {
	if i > 0 {
		depth := d.DomainBitLength - i
		// Parse correction word
		scw := CW[depth].S
		tcwl := CW[depth].Tl
		tcwr := CW[depth].Tr

		// Calculate tau
		tau := dpf.PRG(s, d.prgOutputLength)
		if t {
			appendedSlices := append(scw, boolToByteSlice(tcwl)...)
			appendedSlices = append(appendedSlices, scw...)
			appendedSlices = append(appendedSlices, boolToByteSlice(tcwr)...)
			if len(appendedSlices) != len(tau) {
				return nil, errors.New("length of appended slices does not match length of tau")
			}
			tau = dpf.XORBytes(tau, appendedSlices)
		}

		// Step 5: Parse tau as PRG output
		sl, tl, sr, tr, err := splitPRGOutput(tau, d.Lambda)
		if err != nil {
			return nil, err
		}

		// Define the depth interval for new threads (as otherwise too many threads are created)
		// The switch case is based on the results from the empirical evaluation.
		// We focus on the 20 and 21 bit domain, as these are the most relevant ones for our PCG.
		// The values may depend on the processor used. The values were obtained on an Apple M1 Max with 10 cores.
		// The more cores the processor has, the lower the interval can be chosen as more threads can be efficiently handled simultaneously.
		var threadDepthInterval int
		switch d.DomainBitLength {
		case 20, 21:
			threadDepthInterval = 7
		case 22:
			threadDepthInterval = 6
		default:
			threadDepthInterval = 10 // This implies that no threads are spawned for all domains < 10 bits (as this is inefficient)
		}

		var left, right []*big.Int

		// Function to perform traversal
		doTraverse := func(s []byte, t bool) ([]*big.Int, error) {
			return d.traverseParallel(s, t, CW, i-1, partyID)
		}

		// Check if a new thread should be spawned
		if depth%threadDepthInterval == 0 {
			leftChan := make(chan []*big.Int)
			rightChan := make(chan []*big.Int)
			errChan := make(chan error)

			go func() {
				result, err := doTraverse(sl, tl)
				if err != nil {
					errChan <- err
					return
				}
				leftChan <- result
			}()

			go func() {
				result, err := doTraverse(sr, tr)
				if err != nil {
					errChan <- err
					return
				}
				rightChan <- result
			}()

			for i := 0; i < 2; i++ {
				select {
				case l := <-leftChan:
					left = l
				case r := <-rightChan:
					right = r
				case e := <-errChan:
					if e != nil {
						return nil, e
					}
				}
			}
		} else {
			left, err = doTraverse(sl, tl)
			if err != nil {
				return nil, err
			}
			right, err = doTraverse(sr, tr)
			if err != nil {
				return nil, err
			}
		}

		return append(left, right...), nil

	} else { // i = 0
		// Calculate partial result
		finalSeed := new(big.Int).SetBytes(s)
		partialResult, err := d.evalGroupCalc(finalSeed, CW[d.DomainBitLength].S, partyID, t)
		if err != nil {
			return nil, err
		}
		return []*big.Int{partialResult}, nil
	}
}

// genGroupCalc calculates the group element representation of the final correction word.
func (d *OpTreeDPF) genGroupCalc(finalSeedAlice, finalSeedBob, beta *big.Int, t bool) ([]byte, error) {
	finalSeedAliceC, err := d.convert(finalSeedAlice)
	if err != nil {
		return nil, err
	}
	finalSeedBobC, err := d.convert(finalSeedBob)
	if err != nil {
		return nil, err
	}

	betaC := bls12381.NewFr().FromBytes(beta.Bytes())

	// Calculate beta - finalSeedAliceC + finalSeedBobC:
	finalSeedAliceC.Neg(finalSeedAliceC)
	betaC.Add(betaC, finalSeedAliceC)
	betaC.Add(betaC, finalSeedBobC)

	res := bls12381.NewFr().Set(betaC)
	if t {
		res.Neg(res)
	}

	return res.ToBytes(), nil
}

// evalGroupCalc calculates a partial result from the final seed.
func (d *OpTreeDPF) evalGroupCalc(finalSeed *big.Int, cw []byte, id uint8, t bool) (*big.Int, error) {
	finalSeedC, err := d.convert(finalSeed)
	if err != nil {
		return nil, err
	}
	cwC := bls12381.NewFr().FromBytes(cw)
	res := bls12381.NewFr().Set(finalSeedC)
	if t {
		res.Add(finalSeedC, cwC)
	}
	if id == 1 {
		res.Neg(res)
	}

	return res.ToBig(), nil
}

// convert converts a given big.Int to a group element.
func (d *OpTreeDPF) convert(input *big.Int) (*bls12381.Fr, error) {
	inputExtended, err := dpf.ExtendBigIntToBitLength(input, d.Lambda)
	if err != nil {
		return nil, err
	}
	inputExBytes := dpf.ConvertBitArrayToBytes(inputExtended)

	// BLS12-381 has a prime order, so we can directly return the group element given by the PRG mod q according to the formal definition.
	prgOutput := dpf.PRG(inputExBytes, d.prgOutputLength)
	element := bls12381.NewFr().FromBytes(prgOutput)

	return element, nil
}

// splitPRGOutput splits the output of the PRG into two seeds and two control bits.
func splitPRGOutput(prgOutput []byte, lambda int) ([]byte, bool, []byte, bool, error) {
	lambdaBytes := lambda / 8
	if len(prgOutput) < 2*(lambdaBytes+1) {
		return nil, false, nil, false, errors.New("insufficient length of PRG output")
	}

	sL := prgOutput[:lambdaBytes]
	tL := (prgOutput[lambdaBytes] & 1) != 0 // First bit of the second byte
	sR := prgOutput[lambdaBytes+1 : 2*lambdaBytes+1]
	tR := (prgOutput[2*(lambdaBytes)+1] & 1) != 0 // First bit of the last byte

	return sL, tL, sR, tR, nil
}

func boolToByteSlice(b bool) []byte {
	var byteValue byte
	if b {
		byteValue = 1
	} else {
		byteValue = 0
	}
	return []byte{byteValue}
}
