package pcg

import (
	"encoding/binary"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"math/rand"
	"pcg-master-thesis/pcg/poly"
	"runtime"
	"sort"
	"sync"
)

const forwardDirection = 0
const backwardDirection = 1

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

// Ring defines the ring we work in.
type Ring struct {
	Div   *poly.Polynomial
	Roots []*bls12381.Fr
}

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

// evalFinalShare evaluates the final share of the PCG for the given polynomial.
// This function effectively calculates the inner product between the given polynomial and the random polynomials in div.
func (p *PCG) evalFinalShare(u, rand []*poly.Polynomial, div *poly.Polynomial) (*poly.Polynomial, error) {
	numCores := runtime.NumCPU()
	tasks := make(chan evalFinalShareTask, numCores)
	results := make(chan evalFinalShareResult, p.c)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for task := range tasks {
			prod, err := poly.Mul(task.oprand, task.wPoly)
			if err != nil {
				results <- evalFinalShareResult{nil, err}
				return
			}

			remainder, err := prod.Mod(div)
			results <- evalFinalShareResult{remainder, err}
		}
	}

	for i := 0; i < numCores; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for r := 0; r < p.c; r++ {
			tasks <- evalFinalShareTask{0, 0, rand[r], u[r], div, false} // Indices and isLastIndex are not used here
		}
		close(tasks)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	ai := poly.NewEmpty()
	for i := 0; i < p.c; i++ {
		result := <-results
		if result.err != nil {
			return nil, result.err
		}
		ai.Add(result.poly)
	}

	return ai, nil
}

// evalFinalShare2D evaluates the final share of the PCG for the given polynomial.
// This function effectively calculates the inner product between the given polynomial and the random polynomials in div.
func (p *PCG) evalFinalShare2D(w [][]*poly.Polynomial, oprand []*poly.Polynomial, div *poly.Polynomial) (*poly.Polynomial, error) {
	numCores := runtime.NumCPU()
	tasks := make(chan evalFinalShareTask, numCores)
	results := make(chan evalFinalShareResult, numCores)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for task := range tasks {
			var result evalFinalShareResult
			if task.isLastIndex {
				remainder, err := task.wPoly.Mod(task.div)
				result = evalFinalShareResult{remainder, err}
			} else {
				prod, err := poly.Mul(task.oprand, task.wPoly)
				if err != nil {
					results <- evalFinalShareResult{nil, err}
					return
				}
				result = evalFinalShareResult{prod, err}
			}
			results <- result
		}
	}

	for i := 0; i < numCores; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for j := 0; j < p.c; j++ {
			for k := 0; k < p.c; k++ {
				currentIndex := j*p.c + k
				isLastIndex := currentIndex == p.c*p.c-1
				task := evalFinalShareTask{j, k, oprand[currentIndex], w[j][k], div, isLastIndex}
				tasks <- task
			}
		}
		close(tasks)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	alphai := poly.NewEmpty()
	for range w {
		for range w[0] {
			result := <-results
			if result.err != nil {
				return nil, result.err
			}
			alphai.Add(result.poly)
		}
	}

	return alphai, nil
}

// evalVOLEwithSeed evaluates the VOLE correlation with the given seed.
func (p *PCG) evalVOLEwithSeed(u []*poly.Polynomial, seedSk *bls12381.Fr, seedDSPFKeys [][][]*DSPFKeyPair, seedIndex int, div *poly.Polynomial) ([]*poly.Polynomial, error) {
	utilde := make([]*poly.Polynomial, p.c)
	for r := 0; r < p.c; r++ {
		ur := u[r].DeepCopy()    // We need unmodified u[r] later on, so we copy it
		ur.MulByConstant(seedSk) // u[r] * sk[i]
		for j := 0; j < p.n; j++ {
			if seedIndex != j {
				eval0, err := p.dspfN.FullEvalFastAggregated(seedDSPFKeys[seedIndex][j][r].Key0)
				if err != nil {
					return nil, err
				}
				ur.Add(poly.NewFromFr(eval0))

				eval1, err := p.dspfN.FullEvalFastAggregated(seedDSPFKeys[j][seedIndex][r].Key1)
				if err != nil {
					return nil, err
				}
				ur.Add(poly.NewFromFr(eval1))
			}
		}
		utilde[r] = ur
	}
	return utilde, nil
}

// evalOLEwithSeed evaluates the OLE correlation with the given seed.
func (p *PCG) evalOLEwithSeed(u, v []*poly.Polynomial, seedDSPFKeys [][][][]*DSPFKeyPair, seedIndex int, div *poly.Polynomial) ([][]*poly.Polynomial, error) {
	w := make([][]*poly.Polynomial, p.c)
	for r := 0; r < p.c; r++ {
		w[r] = make([]*poly.Polynomial, p.c)
		for s := 0; s < p.c; s++ {
			var err error
			w[r][s], err = poly.Mul(u[r], v[s]) // u an r are t-sparse -> t*t complexity
			if err != nil {
				return nil, err
			}
			for j := 0; j < p.n; j++ {
				if seedIndex != j { // Ony cross terms
					eval0, err := p.dspf2N.FullEvalFastAggregated(seedDSPFKeys[seedIndex][j][r][s].Key0)
					if err != nil {
						return nil, err
					}
					w[r][s].Add(poly.NewFromFr(eval0)) // N

					eval1, err := p.dspf2N.FullEvalFastAggregated(seedDSPFKeys[j][seedIndex][r][s].Key1)
					if err != nil {
						return nil, err
					}
					w[r][s].Add(poly.NewFromFr(eval1)) // N
				}
			}
		}
	}
	return w, nil
}

// evalVOLEwithSeed evaluates the VOLE correlation with the given seed.
// Poly out is structured as: [j][direction][r], where j is the counter-parties index, direction is 0 for forward and 1 for backward and where r is in c.
func (p *PCG) evalVOLEwithSeedSeparate(seedDSPFKeys [][][]*DSPFKeyPair, seedIndex int) ([][][]*poly.Polynomial, error) {
	utilde := make([][][]*poly.Polynomial, p.n)
	for j := 0; j < p.n; j++ {
		if seedIndex != j {
			utilde[j] = make([][]*poly.Polynomial, 2) // 0 is forward, 1 is backward
			utilde[j][forwardDirection] = make([]*poly.Polynomial, p.c)
			utilde[j][backwardDirection] = make([]*poly.Polynomial, p.c)
			for r := 0; r < p.c; r++ {
				eval0, err := p.dspfN.FullEvalFastAggregated(seedDSPFKeys[seedIndex][j][r].Key0)
				if err != nil {
					return nil, err
				}
				utilde[j][forwardDirection][r] = poly.NewFromFr(eval0)

				eval1, err := p.dspfN.FullEvalFastAggregated(seedDSPFKeys[j][seedIndex][r].Key1)
				if err != nil {
					return nil, err
				}
				utilde[j][backwardDirection][r] = poly.NewFromFr(eval1)
			}
		}
	}
	return utilde, nil
}

// evalOLEwithSeed evaluates the OLE correlation with the given seed.
// Poly out is structured as: [j][r][s], where j is the counter-parties index and r and s are in c.
func (p *PCG) evalOLEwithSeedSeparate(u, v []*poly.Polynomial, seedDSPFKeys [][][][]*DSPFKeyPair, seedIndex int) ([][][]*poly.Polynomial, [][]*poly.Polynomial, error) {
	w := make([][][]*poly.Polynomial, p.n)
	uv := make([][]*poly.Polynomial, p.c)
	for j := 0; j < p.n; j++ {
		if seedIndex != j { // Ony cross terms
			w[j] = make([][]*poly.Polynomial, p.c)
			for r := 0; r < p.c; r++ {
				w[j][r] = make([]*poly.Polynomial, p.c)
				uv[r] = make([]*poly.Polynomial, p.c)
				for s := 0; s < p.c; s++ {
					eval0, err := p.dspf2N.FullEvalFastAggregated(seedDSPFKeys[seedIndex][j][r][s].Key0)
					if err != nil {
						return nil, nil, err
					}
					w[j][r][s] = poly.NewFromFr(eval0)

					eval1, err := p.dspf2N.FullEvalFastAggregated(seedDSPFKeys[j][seedIndex][r][s].Key1)
					if err != nil {
						return nil, nil, err
					}
					w[j][r][s].Add(poly.NewFromFr(eval1))

					uv[r][s], err = poly.Mul(u[r], v[s])
					if err != nil {
						return nil, nil, err
					}
				}
			}

		}
	}
	return w, uv, nil
}

// embedVOLECorrelations embeds VOLE correlations into DSPF keys.
func (p *PCG) embedVOLECorrelations(omega [][][]*big.Int, beta [][][]*bls12381.Fr, skShares []*bls12381.Fr) ([][][]*DSPFKeyPair, error) {
	U := init3DSliceDspfKey(p.n, p.n, p.c)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.n; j++ {
			if i != j {
				for r := 0; r < p.c; r++ {
					skShareIndex := j
					if j > 1 {
						skShareIndex = 1 // TODO: Remove. This is only for testing as we do not interpolate the sk shares
					}

					nonZeroElements := scalarMulFr(skShares[skShareIndex], beta[i][r])
					key0, key1, err := p.dspfN.Gen(omega[i][r], frSliceToBigIntSlice(nonZeroElements))
					if err != nil {
						return nil, err
					}
					U[i][j][r] = &DSPFKeyPair{key0, key1}
				}
			}
		}
	}
	return U, nil
}

// embedOLECorrelations embeds OLE correlations into DSPF keys.
func (p *PCG) embedOLECorrelations(omega, o [][][]*big.Int, beta, b [][][]*bls12381.Fr) ([][][][]*DSPFKeyPair, error) {
	U := init4DSliceDspfKey(p.n, p.n, p.c)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.n; j++ {
			if i != j {
				for r := 0; r < p.c; r++ {
					for s := 0; s < p.c; s++ {
						specialPoints := outerSumBigInt(omega[i][r], o[j][s])
						// For evaluating the performance, we allow duplicates for now
						// if hasDuplicates(specialPoints) {
						//	return nil, fmt.Errorf("special points contain duplicates")
						// }
						nonZeroElements := outerProductFr(beta[i][r], b[j][s])
						key1, key2, err := p.dspf2N.Gen(specialPoints, frSliceToBigIntSlice(nonZeroElements))
						if err != nil {
							return nil, err
						}
						U[i][j][r][s] = &DSPFKeyPair{key1, key2}
					}
				}
			}
		}
	}
	return U, nil
}

// sampleExponents samples values later used as poly exponents by picking p.n*p.c random t-vectors from N.
func (p *PCG) sampleExponents() [][][]*big.Int {
	exp := init3DSliceBigInt(p.n, p.c, p.t)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.c; j++ {
			vec := p.sampleTUniqueExponents()
			sort.Slice(vec, func(i, j int) bool {
				return vec[i].Cmp(vec[j]) < 0
			})
			exp[i][j] = vec
		}
	}
	return exp
}

// sampleCoefficients samples values later used as poly coefficients by picking p.n*p.c random t-vectors from Fq.
func (p *PCG) sampleCoefficients() [][][]*bls12381.Fr {
	exp := init3DSliceFr(p.n, p.c, p.t)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.c; j++ {
			vec := make([]*bls12381.Fr, p.t)
			for t := range vec {
				randElement, _ := bls12381.NewFr().Rand(p.rng)
				vec[t] = bls12381.NewFr()
				vec[t].Set(randElement)
			}
			exp[i][j] = vec
		}
	}
	return exp
}

// constructPolys constructs c t-sparse polynomial from the given coefficients and exponents.
func (p *PCG) constructPolys(coefficients [][]*bls12381.Fr, exponents [][]*big.Int) ([]*poly.Polynomial, error) {
	if len(coefficients) != p.c {
		return nil, fmt.Errorf("amount of coefficient slices is %d but is expected to be c=%d", len(coefficients), p.c)
	}
	if len(exponents) != p.c {
		return nil, fmt.Errorf("amount of exponents slices is %d but is expected to be c=%d", len(coefficients), p.c)
	}

	res := make([]*poly.Polynomial, p.c)
	for r := 0; r < p.c; r++ {
		if len(coefficients[r]) != p.t {
			return nil, fmt.Errorf("amount of coefficients is %d but is expected to be t=%d", len(coefficients[r]), p.t)
		}
		if len(exponents[r]) != p.t {
			return nil, fmt.Errorf("amount of exponents is %d but is expected to be t=%d", len(coefficients[r]), p.t)
		}
		generatedPoly, err := poly.NewSparse(coefficients[r], exponents[r])
		if err != nil {
			return nil, fmt.Errorf("failed to generate polynomial: %w", err)
		}
		res[r] = generatedPoly
	}

	return res, nil
}

// sampleTUniqueExponents samples t unique exponents from N.
func (p *PCG) sampleTUniqueExponents() []*big.Int {
	maxExp := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(p.N)), nil)
	vec := make([]*big.Int, 0, p.t)
	for len(vec) < p.t {
		randNum := big.NewInt(0)
		randNum.Rand(p.rng, maxExp)

		// Check if randNum is already in vec
		exists := false
		for _, num := range vec {
			if num.Cmp(randNum) == 0 {
				exists = true
				break
			}
		}

		if !exists {
			vec = append(vec, randNum)
		}
	}

	return vec
}
