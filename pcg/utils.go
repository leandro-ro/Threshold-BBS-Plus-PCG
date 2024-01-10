package pcg

import (
	"encoding/binary"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"math/rand"
	"pcg-master-thesis/pcg/poly"
	"runtime"
	"sync"
)

// getShamirSharedRandomElement generates a t-out-of-n shamir secret sharing of a random element.
// This function is taken from the threshold-bbs-plus-signatures repository.
func getShamirSharedRandomElement(rng *rand.Rand, t, n int) (*bls12381.Fr, []*bls12381.Fr) {
	// Generate the secret key element
	secretKeyElement := bls12381.NewFr()
	_, err := secretKeyElement.Rand(rng)
	if err != nil {
		panic(err)
	}

	// Shamir Coefficients
	coefficients := make([]*bls12381.Fr, t-1)
	for i := 0; i < t-1; i++ {
		coefficients[i] = bls12381.NewFr()
		_, err := coefficients[i].Rand(rng)
		if err != nil {
			panic(err)
		}
	}

	// Shares
	shares := make([]*bls12381.Fr, n)
	for i := 0; i < n; i++ {
		share := bls12381.NewFr()
		share.Set(secretKeyElement) // Share initialized with secret key element

		incrExponentiation := bls12381.NewFr().One()

		for j := 0; j < t-1; j++ {
			incrExponentiation.Mul(incrExponentiation, uint64ToFr(uint64(i+1)))
			tmp := bls12381.NewFr().Set(coefficients[j])
			tmp.Mul(tmp, incrExponentiation)
			share.Add(share, tmp)
		}

		shares[i] = share
	}
	return secretKeyElement, shares
}

// uint64ToFr converts an uint64 into a bls12381.Fr.
// This function is taken from the threshold-bbs-plus-signatures repository.
func uint64ToFr(val uint64) *bls12381.Fr {
	fr := bls12381.NewFr()
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, val)
	fr.FromBytes(buf)
	return fr
}

// bytesToInt64 converts a byte slice into an int64.
func bytesToInt64(b []byte) (int64, error) {
	// Make sure byte slice has enough bytes to represent a uint64 (8 bytes)
	if len(b) < 8 {
		return 0, fmt.Errorf("byte slice is too short to represent an int64")
	}

	// Convert to uint64 first (you can use BigEndian or LittleEndian)
	val := binary.BigEndian.Uint64(b)

	// Cast uint64 to int64
	return int64(val), nil
}

// outerSumInt calculates the outer sum of two slices of *big.Int.
// the resulting matrix is returned in vector form.
func outerSumBigInt(a, b []*big.Int) []*big.Int {
	result := make([]*big.Int, len(a)*len(b))

	for i, ai := range a {
		baseIndex := i * len(b)
		for j, bj := range b {
			result[baseIndex+j] = new(big.Int).Add(ai, bj)
		}
	}

	return result
}

// outerProductFr calculates the outer product of two slices of *bls12381.Fr.
// the resulting matrix is returned in vector form.
func outerProductFr(a, b []*bls12381.Fr) []*bls12381.Fr {
	result := make([]*bls12381.Fr, len(a)*len(b))

	for i, ai := range a {
		baseIndex := i * len(b)
		for j, bj := range b {
			result[baseIndex+j] = bls12381.NewFr()
			result[baseIndex+j].Mul(ai, bj)
		}
	}

	return result
}

// outerProductPoly calculates the outer product of two slices of *poly.Polynomial.
// The function is implemented using a worker pool to handle large polynomials.
func outerProductPoly(a, b []*poly.Polynomial) ([]*poly.Polynomial, error) {
	numCores := runtime.NumCPU()
	tasks := make(chan polyTask, numCores)
	results := make(chan polyResult, len(a)*len(b))
	errs := make(chan error, 1)

	// Worker function for polynomial multiplication
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for task := range tasks {
			prod, err := poly.Mul(task.aPoly, task.bPoly)
			if err != nil {
				errs <- err
				return
			}
			results <- polyResult{task.aIndex, task.bIndex, prod}
		}
	}

	// Start workers
	for i := 0; i < numCores; i++ {
		wg.Add(1)
		go worker()
	}

	// Distribute tasks
	go func() {
		for i, aPoly := range a {
			for j, bPoly := range b {
				tasks <- polyTask{i, j, aPoly, bPoly}
			}
		}
		close(tasks)
	}()

	// Wait for workers to complete and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	res := make([]*poly.Polynomial, len(a)*len(b))
	for result := range results {
		i, j := result.aIndex, result.bIndex
		res[i*len(b)+j] = result.product
	}

	// Check for errors
	select {
	case err := <-errs:
		return nil, err
	default:
	}

	return res, nil
}

// scalarMulFr multiplies a scalar with a vector of *bls12381.Fr.
func scalarMulFr(scalar *bls12381.Fr, vector []*bls12381.Fr) []*bls12381.Fr {
	result := make([]*bls12381.Fr, len(vector))
	for i := 0; i < len(vector); i++ {
		result[i] = bls12381.NewFr()
		result[i].Mul(scalar, vector[i])
	}
	return result
}

// init3DSliceBigInt initializes a 3D slice of *big.Int
func init3DSliceBigInt(n, m, p int) [][][]*big.Int {
	slice := make([][][]*big.Int, n)
	for i := range slice {
		slice[i] = make([][]*big.Int, m)
		for j := range slice[i] {
			slice[i][j] = make([]*big.Int, p)
			for k := range slice[i][j] {
				slice[i][j][k] = new(big.Int)
			}
		}
	}
	return slice
}

// init3DSliceFr initializes a 3D slice of *bls12381.Fr
func init3DSliceFr(n, m, p int) [][][]*bls12381.Fr {
	slice := make([][][]*bls12381.Fr, n)
	for i := range slice {
		slice[i] = make([][]*bls12381.Fr, m)
		for j := range slice[i] {
			slice[i][j] = make([]*bls12381.Fr, p)
			for k := range slice[i][j] {
				slice[i][j][k] = bls12381.NewFr()
			}
		}
	}
	return slice
}

// init3DSliceDspfKey initializes a 3D slice of *DSPFKeyPair
func init3DSliceDspfKey(n, m, p int) [][][]*DSPFKeyPair {
	slice := make([][][]*DSPFKeyPair, n)
	for i := range slice {
		slice[i] = make([][]*DSPFKeyPair, m)
		for j := range slice[i] {
			slice[i][j] = make([]*DSPFKeyPair, p)
			for k := range slice[i][j] {
				slice[i][j][k] = new(DSPFKeyPair)
			}
		}
	}
	return slice
}

// init4DSliceDspfKey initializes a 3D slice of *DSPFKeyPair
func init4DSliceDspfKey(n, m, p int) [][][][]*DSPFKeyPair {
	slice := make([][][][]*DSPFKeyPair, n)
	for i := range slice {
		slice[i] = make([][][]*DSPFKeyPair, m)
		for j := range slice[i] {
			slice[i][j] = make([][]*DSPFKeyPair, p)
			for k := range slice[i][j] {
				slice[i][j][k] = make([]*DSPFKeyPair, p)
				for p := range slice[i][j][k] {
					slice[i][j][k][p] = new(DSPFKeyPair)
				}
			}
		}
	}
	return slice
}

// frSliceToBigIntSlice converts a slice of *bls12381.Fr to a slice of *big.Int
func frSliceToBigIntSlice(s []*bls12381.Fr) []*big.Int {
	result := make([]*big.Int, len(s))
	for i, e := range s {
		result[i] = e.ToBig()
	}
	return result
}

func hasDuplicates(slice []*big.Int) bool {
	seen := make(map[string]struct{})
	for _, value := range slice {
		// Convert *big.Int to a string for comparison, as map keys need to be comparable
		strValue := value.String()
		if _, exists := seen[strValue]; exists {
			// Duplicate found
			return true
		}
		seen[strValue] = struct{}{}
	}
	return false
}

func aggregateDSPFoutput(output [][]*big.Int) []*bls12381.Fr {
	sums := make([]*bls12381.Fr, len(output[0]))
	for i := 0; i < len(output[0]); i++ {
		for j := 0; j < len(output); j++ {
			if sums[i] == nil {
				sums[i] = bls12381.NewFr()
			}
			val := bls12381.NewFr().FromBytes(output[j][i].Bytes())
			sums[i].Add(sums[i], val)
		}
	}

	return sums
}

// primeFactor represents a prime factor and its exponent.
type primeFactor struct {
	Factor   *big.Int // The prime factor
	Exponent int      // The exponent of the prime factor
}

// multiplicativeGroupOrderFactorizationBLS12381 returns the prime factorization of the multiplicative group order -1 of BLS12381.
// For performance reasons the factors are hardcoded.
// Constants are taken from https://github.com/hyperproofs/go-mcl/blob/master/mcl_extra.go
func multiplicativeGroupOrderFactorizationBLS12381() []primeFactor {
	// Define the prime factors and their exponents
	factors := []int64{2, 3, 11, 19, 10177, 125527, 859267, 906349, 2508409, 2529403, 52437899, 254760293}
	multiplicities := []int{32, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2}

	// Slice to hold the PrimeFactor structs
	var primeFactors []primeFactor

	// Iterate over the factors and their multiplicities
	for i, factor := range factors {
		primeFactors = append(primeFactors, primeFactor{
			Factor:   big.NewInt(factor),
			Exponent: multiplicities[i],
		})
	}

	return primeFactors
}

// The following structs support parallel processing

// evalFinalShareTask represents a task for the eval2D function.
type evalFinalShareTask struct {
	j, k        int
	oprand      *poly.Polynomial
	wPoly       *poly.Polynomial
	div         *poly.Polynomial
	isLastIndex bool
}

// evalFinalShareResult represents the result of the eval2D function.
type evalFinalShareResult struct {
	poly *poly.Polynomial
	err  error
}

// polyTask represents a task for the polynomial multiplication.
type polyTask struct {
	aIndex int
	bIndex int
	aPoly  *poly.Polynomial
	bPoly  *poly.Polynomial
}

// polyResult represents the result of the polynomial multiplication.
type polyResult struct {
	aIndex  int
	bIndex  int
	product *poly.Polynomial
}
