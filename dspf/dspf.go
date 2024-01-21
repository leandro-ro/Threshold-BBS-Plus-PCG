package dspf

import (
	"errors"
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"pcg-master-thesis/dpf"
	"runtime"
	"sync"
)

// DSPF is a Distributed Sum Of Point Function. It uses multiple DPFs to realize a multipoint function.
type DSPF struct {
	baseDPF dpf.DPF // The base DPF used to construct the DSPF
}

// NewDSPFFactory creates a new DSPF factory with a given base DPF and domain.
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

	// Check for duplicates in specialPoints // TODO: For now, we allow duplicates although this is not secure
	// seen := make(map[string]struct{})
	// for i, sp := range specialPoints {
	//	if sp == nil || nonZeroElements[i] == nil {
	//		return Key{}, Key{}, errors.New("special points and non-zero elements cannot be nil")
	//	}

	// Use string representation of big.Int for map key
	// spStr := sp.Text(10) // Base 10 for decimal representation
	// if _, exists := seen[spStr]; exists {
	// 	return Key{}, Key{}, fmt.Errorf("duplicate special point: %s", spStr)
	// }
	// seen[spStr] = struct{}{}
	//}

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

// CombineMultipleResults combines the results from multiple (e.g. full) key evaluations.
func (d *DSPF) CombineMultipleResults(y1 [][]*big.Int, y2 [][]*big.Int) ([]*big.Int, error) {
	if len(y1) != len(y2) {
		return nil, errors.New("length of y1 and y2 must match")
	}
	combined := make([]*big.Int, len(y1))
	for i := range y1 {
		res, err := d.CombineSingleResult(y1[i], y2[i])
		if err != nil {
			return nil, err
		}
		combined[i] = big.NewInt(0)
		combined[i].Set(res)
	}
	return combined, nil
}

// CombineSingleResult combines the results from a single key evaluation.
func (d *DSPF) CombineSingleResult(y1 []*big.Int, y2 []*big.Int) (*big.Int, error) {
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

// FullEval evaluates each DPF of the DSPF on all points in the domain.
func (d *DSPF) FullEval(dspfKey Key) ([][]*big.Int, error) {
	ys := make([][]*big.Int, len(dspfKey.DPFKeys))
	for i, key := range dspfKey.DPFKeys {
		y, err := d.baseDPF.FullEval(key)
		if err != nil {
			return nil, err
		}
		ys[i] = y
	}
	return ys, nil
}

// FullEvalFast evaluates each DPF of the DSPF on all points in the domain.
// It parallelizes the evaluation of each DPF.
// Warning: For large Domains use FullEvalFastAggregated instead to avoid memory issues.
func (d *DSPF) FullEvalFast(dspfKey Key) ([][]*big.Int, error) {
	ys := make([][]*big.Int, len(dspfKey.DPFKeys))
	errCh := make(chan error, 1)
	wg := sync.WaitGroup{}

	for i, key := range dspfKey.DPFKeys {
		wg.Add(1)
		go func(i int, key dpf.Key) {
			defer wg.Done()

			y, err := d.baseDPF.FullEvalFast(key)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}

			ys[i] = y
		}(i, key)
	}

	wg.Wait()
	close(errCh)

	if err, ok := <-errCh; ok {
		return nil, err
	}

	return ys, nil
}

type AggregatedResult struct {
	ys  []*bls12381.Fr
	mtx sync.Mutex
}

// FullEvalFastAggregated evaluates each DPF of the DSPF on all points in the domain.
// It parallelizes the evaluation of each DPF. It aggregates the results in a single result.
// This also uses a worker pool to parallelize the aggregation efficiently in oder to avoid memory issues.
func (d *DSPF) FullEvalFastAggregated(dspfKey Key) ([]*bls12381.Fr, error) {
	expectedLen := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(d.baseDPF.GetDomain())), nil)
	numWorkers := runtime.NumCPU()

	aggResult := AggregatedResult{
		ys: make([]*bls12381.Fr, expectedLen.Int64()),
	}
	for i := range aggResult.ys {
		aggResult.ys[i] = bls12381.NewFr().Zero()
	}

	errCh := make(chan error, 1)
	jobsCh := make(chan dpf.Key, len(dspfKey.DPFKeys))
	resultsCh := make(chan []*big.Int, len(dspfKey.DPFKeys))
	wg := sync.WaitGroup{}

	// Start workers
	for w := 0; w < numWorkers; w++ {
		go func() {
			for key := range jobsCh {
				y, err := d.baseDPF.FullEvalFast(key)
				if err != nil {
					errCh <- err
					return
				}
				resultsCh <- y
			}
		}()
	}

	// Send jobs
	for _, key := range dspfKey.DPFKeys {
		wg.Add(1)
		jobsCh <- key
	}
	close(jobsCh)

	// Handle results
	var aggError error
	go func() {
		for range dspfKey.DPFKeys {
			select {
			case y := <-resultsCh:
				aggResult.mtx.Lock()
				for i, bigIntVal := range y {
					val := bls12381.NewFr().FromBytes(bigIntVal.Bytes())
					aggResult.ys[i].Add(aggResult.ys[i], val)
				}
				aggResult.mtx.Unlock()
				wg.Done()
			case err := <-errCh:
				if aggError == nil {
					aggError = err
				}
				close(resultsCh)
				wg.Done()
				return
			}
		}
	}()

	wg.Wait()

	if aggError != nil {
		return nil, aggError
	}

	return aggResult.ys, nil
}
