package dspf

import (
	"errors"
	"fmt"
	"math/big"
	"pcg-master-thesis/dpf"
)

// DSPF is a Distrubuted Sun Of Point Function. It uses multiple DPFs to realize a multipoint function.
type DSPF struct {
	baseDPF dpf.DPF // The base DPF used to construct the DSPF
}

// Gen generates keys for a DSPFt given t special points and non-zero elements.
func (d *DSPF) Gen(specialPoints []*big.Int, nonZeroElements []*big.Int) (Key, Key, error) {
	// Check if the inputs are valid: same length and non-nil
	if len(specialPoints) != len(nonZeroElements) {
		return Key{}, Key{}, errors.New("the number of special points and non-zero elements must match")
	}

	// Check for duplicates in specialPoints
	seen := make(map[string]struct{})
	for i, sp := range specialPoints {
		if sp == nil || nonZeroElements[i] == nil {
			return Key{}, Key{}, errors.New("special points and non-zero elements cannot be nil")
		}

		// Use string representation of big.Int for map key
		spStr := sp.Text(10) // Base 10 for decimal representation
		if _, exists := seen[spStr]; exists {
			return Key{}, Key{}, fmt.Errorf("duplicate special point: %s", spStr)
		}
		seen[spStr] = struct{}{}
	}

	// Generate DPF keys for each (specialPoint, nonZeroElement) pair
	var keyAlice Key
	var keyBob Key
	for i, sp := range specialPoints {
		key1, key2, err := d.baseDPF.Gen(sp, nonZeroElements[i])
		if err != nil {
			return Key{}, Key{}, err
		}
		keyAlice.DPFKeys = append(keyAlice.DPFKeys, key1)
		keyBob.DPFKeys = append(keyBob.DPFKeys, key2)
	}
	return keyAlice, keyBob, nil
}

// Eval evaluates the DSPFt on a given point x.
func (d *DSPF) Eval(dspfKey DSPFKey, x *big.Int) (*big.Int, error) {
	// Deserialize the dspfKey to get the individual DPF keys
	dpfKeys, err := deserializeDSPFKey(dspfKey)
	if err != nil {
		return nil, err
	}

	// Evaluate each DPF key and sum the results
	sum := big.NewInt(0)
	for _, key := range dpfKeys {
		y, err := d.dpf.Eval(key, x)
		if err != nil {
			return nil, err
		}
		sum.Add(sum, y)
	}
	return sum, nil
}

// CombineResults combines the results from the evaluations of DSPF keys.
func (d *dspfImpl) CombineResults(results ...*big.Int) *big.Int {
	combined := big.NewInt(0)
	for _, r := range results {
		combined.Add(combined, r)
	}
	return combined
}

// We would also need to define the DSPFKey structure and methods for serialization/deserialization.
// ...
