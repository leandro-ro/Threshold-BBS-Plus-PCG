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
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	secp256k1fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"sync"

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
	PrgOutputLength int      // PrgOutputLength sets how many bytes the PRG used in the TreeDPF returns.
	BetaMax         *big.Int // BetaMax is the maximum value of the non-zero element.
}

// InitFactory initializes a new OpTreeDPF structure with the given security parameter lambda.
// It returns an error if lambda is not one of the allowed values (128, 192, 256).
func InitFactory(lambda int) (*OpTreeDPF, error) {
	// Select the curve. We will use the group order of the curve for the group operations.
	var curve ecc.ID
	switch lambda {
	case 128, 192, 256:
		curve = ecc.SECP256K1 // This limits the non-zero elm to 256 bits
	default:
		return nil, errors.New("lambda must be 128, 192, or 256")
	}

	prgOutputLength := 2 * (lambda/8 + 1)

	return &OpTreeDPF{
		Lambda:          lambda,
		PrgOutputLength: prgOutputLength,
		BetaMax:         new(big.Int).Sub(curve.BaseField(), big.NewInt(1)),
	}, nil
}

// Gen generates two DPF keys based on a given special point and non-zero element.
// This method follows the Gen algorithm described in the aforementioned paper.
func (d *OpTreeDPF) Gen(specialPointX *big.Int, nonZeroElementY *big.Int) (dpf.Key, dpf.Key, error) {
	// Choosing n as lambda is a practical consideration. N needs to be constant for all evaluations,
	// S.t. the all input values besides the special point will evaluate to zero in Eval.
	// Otherwise, the depth of the tree will vary and the zero requirement of the DPF is not met.
	n := d.Lambda
	if specialPointX.BitLen() > d.Lambda {
		return &Key{}, &Key{}, errors.New("the special point is too large. It must be within [0, 2^Lambda - 1]")

	}

	beta := nonZeroElementY // This is just syntactic sugar to resemble the formal description of the algorithm.
	if beta.Cmp(d.BetaMax) == 1 {
		return &Key{}, &Key{}, errors.New("the non-zero element is too large for the group order used")
	}

	// Extend the bit length of specialPointX to lambda.
	alpha, err := dpf.ExtendBigIntToBitLength(specialPointX, d.Lambda)
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
			prgOutput := dpf.PRG(s[party][i-1], d.PrgOutputLength)
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

	n := d.Lambda
	if x.BitLen() > d.Lambda {
		return nil, errors.New("the given point is too large. It must be within [0, 2^Lambda - 1]")
	}

	a, err := dpf.ExtendBigIntToBitLength(x, n)
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
		tau := dpf.PRG(s, d.PrgOutputLength)
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
	y1C := new(secp256k1fp.Element).SetBigInt(y1)
	y2C := new(secp256k1fp.Element).SetBigInt(y2)

	res := new(secp256k1fp.Element).Add(y1C, y2C)

	resBytes := res.Bytes()
	result := new(big.Int).SetBytes(resBytes[:])
	return result
}

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

	var leafCounter = SafeCounter{}
	r := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(128)), nil)
	leafCounter.SetTotal(r)

	res, err := d.traverse(initS, initT, tkey.CW, d.Lambda, tkey.ID, &leafCounter)
	if err != nil {
		return nil, err
	}
	return res, nil
}

type SafeCounter struct {
	mu        sync.Mutex
	count     *big.Int
	total     *big.Int
	lastPrint *big.Int
}

func (c *SafeCounter) Increment() {
	c.mu.Lock()
	if c.count == nil {
		c.count = big.NewInt(0)
	}
	c.count = c.count.Add(c.count, big.NewInt(1))
	c.mu.Unlock()
}

func (c *SafeCounter) SetTotal(total *big.Int) {
	c.mu.Lock()
	c.total = total
	c.lastPrint = big.NewInt(0)
	c.mu.Unlock()
}

func (c *SafeCounter) Progress() (bool, *big.Int, *big.Int, float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Convert count and total to big.Float
	floatCount := new(big.Float).SetInt(c.count)
	floatTotal := new(big.Float).SetInt(c.total)

	// Perform the division
	quotient := new(big.Float).Quo(floatCount, floatTotal)

	// Convert the quotient to a float64 and multiply by 100 for the percentage
	percentage, _ := quotient.Mul(quotient, big.NewFloat(100)).Float64()

	delta := new(big.Int).Sub(c.count, c.lastPrint)
	if delta.Cmp(big.NewInt(100000)) == 1 {
		c.lastPrint.Set(c.count)
		return true, c.count, c.total, percentage
	}

	return false, c.count, c.total, percentage
}

func (d *OpTreeDPF) traverse(s []byte, t bool, CW map[int]CorrectionWord, i int, partyID uint8, progressCounter *SafeCounter) ([]*big.Int, error) {
	currentDepth := i - d.Lambda

	if i > 0 {
		// Parse correction word
		scw := CW[i-1].S
		tcwl := CW[i-1].Tl
		tcwr := CW[i-1].Tr

		// Calculate tau
		tau := dpf.PRG(s, d.PrgOutputLength)
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

		// Define the depth interval for new threads
		const threadDepthInterval = 10 // Adjust based on your requirements

		var left, right []*big.Int

		// Function to perform traversal
		doTraverse := func(s []byte, t bool) ([]*big.Int, error) {
			return d.traverse(s, t, CW, i-1, partyID, progressCounter)
		}

		// Check if a new thread should be spawned
		if currentDepth%threadDepthInterval == 0 {
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
		partialResult, err := d.evalGroupCalc(finalSeed, CW[d.Lambda].S, partyID, t)
		if err != nil {
			return nil, err
		}

		progressCounter.Increment()
		if big.NewInt(0).Mod(partialResult, big.NewInt(128)).Cmp(big.NewInt(0)) != 0 {
			p, current, total, percentage := progressCounter.Progress()
			if p {
				fmt.Printf("Processed leaves: %d/%d (%.5f%%)\n", current, total, percentage)

			}
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

	betaC := new(secp256k1fp.Element).SetBigInt(beta) // No conversion here, as we would lose beta with this

	// Calculate beta - finalSeedAliceC + finalSeedBobC:
	finalSeedAliceCNeg := new(secp256k1fp.Element).Neg(finalSeedAliceC)
	sumBeta := new(secp256k1fp.Element).Add(betaC, finalSeedAliceCNeg)
	sum := new(secp256k1fp.Element).Add(sumBeta, finalSeedBobC)

	res := new(secp256k1fp.Element).Set(sum)
	if t {
		res.Neg(res)
	}

	resBytes := res.Bytes() // We need to slice the result to get from [32]byte to generic []byte
	result := resBytes[:]

	return result, nil
}

// evalGroupCalc calculates a partial result from the final seed.
func (d *OpTreeDPF) evalGroupCalc(finalSeed *big.Int, cw []byte, id uint8, t bool) (*big.Int, error) {
	finalSeedC, err := d.convert(finalSeed)
	if err != nil {
		return nil, err
	}
	cwC := new(secp256k1fp.Element).SetBytes(cw)
	res := new(secp256k1fp.Element).Set(finalSeedC)
	if t {
		res.Add(finalSeedC, cwC)
	}
	if id == 1 {
		res.Neg(res)
	}

	resBytes := res.Bytes()
	result := new(big.Int).SetBytes(resBytes[:])

	return result, nil
}

// convert converts a given big.Int to a group element.
func (d *OpTreeDPF) convert(input *big.Int) (*secp256k1fp.Element, error) {
	inputExtended, err := dpf.ExtendBigIntToBitLength(input, d.Lambda)
	if err != nil {
		return nil, err
	}
	inputExBytes := dpf.ConvertBitArrayToBytes(inputExtended)

	// The SECP256K1 curve has a prime order q, so we can directly return the group element given by the PRG mod q.
	prgOutput := dpf.PRG(inputExBytes, d.PrgOutputLength)
	prgOutputInt := new(big.Int).SetBytes(prgOutput)

	element := new(secp256k1fp.Element)
	element.SetBigInt(prgOutputInt) // Includes Mod operation

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
