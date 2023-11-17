package dspf

import (
	"errors"
	"fmt"
	"math/big"
	"pcg-master-thesis/dpf"
)

// DSPF is a Distributed Sum Of Point Function. It uses multiple DPFs to realize a multipoint function.
type DSPF struct {
	baseDPF dpf.DPF // The base DPF used to construct the DSPF
}

func NewDSPFFactory(baseDPF dpf.DPF) *DSPF {
	return &DSPF{
		baseDPF: baseDPF,
	}
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
func (d *DSPF) Eval(dspfKey Key, x *big.Int) ([]*big.Int, error) {
	ys := make([]*big.Int, len(dspfKey.DPFKeys))
	for i, key := range dspfKey.DPFKeys {
		y, err := d.baseDPF.Eval(key, x)
		if err != nil {
			return nil, err
		}
		ys[i] = y
	}
	return ys, nil
}

// CombineResults combines the results from the evaluations of DSPF key.
func (d *DSPF) CombineResults(y1 []*big.Int, y2 []*big.Int) (*big.Int, error) {
	if len(y1) != len(y2) {
		return nil, errors.New("length of y1 and y2 must match")
	}

	nonZeroPointFound := false
	combined := big.NewInt(0)
	zero := big.NewInt(0)
	for i, y := range y1 {
		res := d.baseDPF.CombineResults(y, y2[i])

		if res.Cmp(zero) != 0 && !nonZeroPointFound {
			nonZeroPointFound = true
			combined.Add(combined, res)
		} else if res.Cmp(zero) != 0 && nonZeroPointFound {
			return nil, errors.New("multiple non-zero elements found for this x")
		}
	}
	return combined, nil
}
