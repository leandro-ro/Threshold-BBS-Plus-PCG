package pcg

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"log"
	"math/big"
	"math/rand"
	"pcg-master-thesis/dpf"
	optreedpf "pcg-master-thesis/dpf/2018_boyle_optimization"
	"pcg-master-thesis/dspf"
	"pcg-master-thesis/pcg/poly"
	"runtime"
	"sort"
	"sync"
	"time"
)

type PCG struct {
	lambda int        // lambda is the security parameter used to determine the output length of the underlying PRandomG
	N      int        // N is the domain of the PCG. For given N, the PCG is able to generate up to 2^N BBS+ tuples.
	n      int        // n is the number of parties participating in this PCG
	c      int        // c is the first security parameter of the Module-LPN assumption
	t      int        // t is the second security parameter of the Module-LPN assumption
	dspfN  *dspf.DSPF // dpfN is the Distributed Sum of Point Function used to construct the PCG with domain N
	dspf2N *dspf.DSPF // dpf2N is the Distributed Sum of Point Function used to construct the PCG with domain 2N
	rng    *rand.Rand // rng is the random number generator used to sample the PCG seeds
}

// NewPCG creates a new PCG with the given parameters.
// It uses OptreeDPF as the underlying DPF.
func NewPCG(lambda, N, n, c, t int) (*PCG, error) {
	seed, _ := bytesToInt64(dpf.RandomSeed(8))
	rng := rand.New(rand.NewSource(seed)) // TODO: Swap this out for a secure PRG

	// TODO: Make base DPF exchangeable
	baseDpfDomain, err := optreedpf.InitFactory(lambda, N)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize base DPF with domain N: %w", err)
	}
	baseDpfDoubleDomain, err := optreedpf.InitFactory(lambda, N+1) // 2^N, therefore double the domain size with +1
	if err != nil {
		return nil, fmt.Errorf("failed to initialize base DPF with domain 2N: %w", err)
	}

	return &PCG{
		lambda: lambda,
		N:      N,
		n:      n,
		c:      c,
		t:      t,
		dspfN:  dspf.NewDSPFFactoryWithDomain(baseDpfDomain, N),
		dspf2N: dspf.NewDSPFFactoryWithDomain(baseDpfDoubleDomain, N+1),
		rng:    rng,
	}, nil
}

// Define the ring we are working with.
func (p *PCG) GetRing(useCyclotomic bool) (*Ring, error) {
	// Define the Ring we work in
	smallFactorThreshold := big.NewInt(1000)
	groupOrderFactorization := multiplicativeGroupOrderFactorizationBLS12381()

	smallFactors := make([]primeFactor, 0)
	for i := 0; i < len(groupOrderFactorization); i++ {
		if groupOrderFactorization[i].Factor.Cmp(smallFactorThreshold) < 0 {
			smallFactors = append(smallFactors, groupOrderFactorization[i])
		}
	}

	smoothOrder := big.NewInt(1)
	for i := 0; i < len(smallFactors); i++ {
		val := big.NewInt(0)
		val.Exp(smallFactors[i].Factor, big.NewInt(int64(smallFactors[i].Exponent)), nil)
		smoothOrder.Mul(smoothOrder, val)
	}

	groupOrder := big.NewInt(0)
	groupOrder.SetString(poly.FrModulus, 16) // BLS12-381 group order

	primitiveRootOfUnity := big.NewInt(0)
	primitiveRootOfUnity.SetString(poly.FrPrimitiveRootOfUnity, 16) // BLS12-381 primitive root of unity for FrModulus

	// Compute primitiveRootOfUnity^((groupOrder-1)/smoothOrder) mod groupOrder
	exp := new(big.Int).Sub(groupOrder, big.NewInt(1))
	exp.Div(exp, smoothOrder)
	multiplicativeSmoothGroupGenerator := new(big.Int).Exp(primitiveRootOfUnity, exp, groupOrder)

	twoPowN := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(p.N)), nil)
	modCheck := new(big.Int).Mod(smoothOrder, twoPowN)
	if !(modCheck.Cmp(big.NewInt(0)) == 0) {
		return nil, fmt.Errorf("order must divide multiplactive group order of BLS12-381")
	}

	smoothOrderDivN := new(big.Int).Div(smoothOrder, twoPowN)
	powerIteratorBase := new(big.Int).Exp(multiplicativeSmoothGroupGenerator, smoothOrderDivN, groupOrder)

	// init div as 1 poly
	div := poly.NewFromFr([]*bls12381.Fr{bls12381.NewFr().One()})
	roots := make([]*bls12381.Fr, twoPowN.Int64())
	for i := 0; i < int(twoPowN.Int64()); i++ {
		if useCyclotomic {
			val := new(big.Int).Exp(powerIteratorBase, big.NewInt(int64(i+1)), groupOrder)
			roots[i] = bls12381.NewFr().FromBytes(val.Bytes())
		} else {
			val, err := bls12381.NewFr().Rand(p.rng)
			if err != nil {
				return nil, err
			}

			bZero := big.NewInt(0).Sub(groupOrder, val.ToBig())
			bOne := big.NewInt(1)
			b := poly.NewFromBig([]*big.Int{bZero, bOne})

			err = div.Mul(b)
			if err != nil {
				return nil, err
			}

			roots[i] = val
		}

	}

	if useCyclotomic {
		div, _ = poly.NewCyclotomicPolynomial(twoPowN) // div = x^N^2 + neg(1)
	}

	return &Ring{div, roots}, nil
}

// TrustedSeedGen generates a seed for each party via a central dealer.
// The goal is to realize a distributed generation.
func (p *PCG) TrustedSeedGen() ([]*Seed, error) {
	// Notation of the variables analogue to the notation from the formal definition of PCG
	// 1. Generate key shares for each party
	_, skShares := getShamirSharedRandomElement(p.rng, p.n, p.n) // TODO: determine how we want to set the threshold for the signature scheme

	// 2a. Initialize aOmega, eEta, and sPhi by sampling at random from N
	aOmega := p.sampleExponents() // a
	eEta := p.sampleExponents()   // e
	sPhi := p.sampleExponents()   // s

	// 2b. Initialize aBeta, eGamma and sEpsilon by sampling at random from F_q (via bls12381.Fr)
	aBeta := p.sampleCoefficients()    // a
	eGamma := p.sampleCoefficients()   // e
	sEpsilon := p.sampleCoefficients() // s

	// 3. Embed first part of delta (delta0) correlation (sk*a)
	U, err := p.embedVOLECorrelations(aOmega, aBeta, skShares)
	if err != nil {
		return nil, fmt.Errorf("step 3: failed to generate DSPF keys for first part of delta VOLE correlation (sk * a): %w", err)
	}

	// 4a. Embed alpha correlation (a*s)
	C, err := p.embedOLECorrelations(aOmega, sPhi, aBeta, sEpsilon)
	if err != nil {
		return nil, fmt.Errorf("step 4: failed to generate DSPF keys for alpha OLE correlation (a * s): %w", err)
	}

	// 4b. Embed second part of delta (delta1) correlation (a*e)
	V, err := p.embedOLECorrelations(aOmega, eEta, aBeta, eGamma)
	if err != nil {
		return nil, fmt.Errorf("step 4: failed to generate DSPF keys for second part of delta OLE correlation (a * e): %w", err)
	}

	// 5. Generate seed for each party
	seeds := make([]*Seed, p.n)
	for i := 0; i < p.n; i++ {
		seeds[i] = &Seed{
			index: i,
			ski:   skShares[i],
			exponents: seedExponents{
				aOmega: aOmega[i],
				eEta:   eEta[i],
				sPhi:   sPhi[i],
			},
			coefficients: seedCoefficients{
				aBeta:    aBeta[i],
				eGamma:   eGamma[i],
				sEpsilon: sEpsilon[i],
			},
			U: U, // TODO: We are currently sending all U, C and V to each party. This is not necessary, as each party only needs the U, C and V for their index
			C: C,
			V: V,
		}
	}

	return seeds, nil
}

// Eval evaluates the PCG for the given seed based on a c random polynomials.
func (p *PCG) Eval(seed *Seed, rand []*poly.Polynomial, div *poly.Polynomial) (*BBSPlusTupleGenerator, error) {
	startTimeTotal := time.Now()
	if len(rand) != p.c {
		return nil, fmt.Errorf("rand must hold c=%d polynomials but contains %d", p.c, len(rand))
	}
	one, _ := poly.NewSparse([]*bls12381.Fr{bls12381.NewFr().FromBytes(big.NewInt(1).Bytes())}, []*big.Int{big.NewInt(0)}) // = 1
	if !rand[p.c-1].Equal(one) {
		return nil, fmt.Errorf("rand must be a slice of polynomials with polynomial of the the last index rand[c-1] equal to 1")
	}

	//log.Println("Evaluating PCG for ", seed.index)
	// 1. Generate polynomials
	//log.Println("Generating polynomials")
	startGenPolys := time.Now()
	u, err := p.constructPolys(seed.coefficients.aBeta, seed.exponents.aOmega)
	if err != nil {
		return nil, fmt.Errorf("step 1: failed to generate polynomials for u from aBeta and aOmega: %w", err)
	}
	v, err := p.constructPolys(seed.coefficients.eGamma, seed.exponents.eEta)
	if err != nil {
		return nil, fmt.Errorf("step 1: failed to generate polynomials for v from eGamma and eEta: %w", err)
	}
	k, err := p.constructPolys(seed.coefficients.sEpsilon, seed.exponents.sPhi)
	if err != nil {
		return nil, fmt.Errorf("step 1: failed to generate polynomials for k from sEpsilon and sPhi: %w", err)
	}
	endGenPolys := time.Now()
	duration := endGenPolys.Sub(startGenPolys)
	log.Println("Generated polynomials (in s): ", duration.Seconds())

	// 2. Process VOLE (u) with seed / delta0 = ask
	//log.Println("Processing VOLE (delta0 = ask)")
	startVole := time.Now()
	utilde, err := p.evalVOLEwithSeed(u, seed.ski, seed.U, seed.index, div)
	if err != nil {
		return nil, fmt.Errorf("step 2: failed to evaluate VOLE (utilde): %w", err)
	}
	endVole := time.Now()
	duration = endVole.Sub(startVole)
	log.Println("Processed VOLE (in s): ", duration.Seconds())

	// 3. Process first OLE correlation (u, k) with seed / alpha = as
	//log.Println("Processing #1 OLE (alpha = as)")
	startOle := time.Now()
	w, err := p.evalOLEwithSeed(u, k, seed.C, seed.index, div)
	if err != nil {
		return nil, fmt.Errorf("step 3: failed to evaluate OLE (w): %w", err)
	}
	endOle := time.Now()
	duration = endOle.Sub(startOle)
	log.Println("Processed #1 OLE (in s): ", duration.Seconds())

	// 4. Process second OLE correlation (u, v) with seed /  delta1 = ae
	//log.Println("Processing #2 OLE (delta1 = ae)")
	startOle2 := time.Now()
	m, err := p.evalOLEwithSeed(u, v, seed.V, seed.index, div)
	if err != nil {
		return nil, fmt.Errorf("step 4: failed to evaluate OLE (m): %w", err)
	}
	endOle2 := time.Now()
	duration = endOle2.Sub(startOle2)
	log.Println("Processed #2 OLE (in s): ", duration.Seconds())

	// 5. Calculate final shares
	//log.Println("Calculating final share polynomials")
	ai, err := p.evalFinalShare(u, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ai: %w", err)
	}
	ei, err := p.evalFinalShare(v, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ei: %w", err)
	}
	si, err := p.evalFinalShare(k, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ki: %w", err)
	}

	startFinalShareVOLE := time.Now()
	delta0i, err := p.evalFinalShare(utilde, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share delta0i: %w", err)
	}
	endFinalShareVOLE := time.Now()
	duration = endFinalShareVOLE.Sub(startFinalShareVOLE)
	log.Println("Calculated final share polynomials for VOLE (in s): ", duration.Seconds())

	oprand, err := outerProductPoly(rand, rand)
	if err != nil {
		return nil, err
	}

	//log.Println("Calculating final share polynomials 2D")
	startFinalShareOLE := time.Now()
	alphai, err := p.evalFinalShare2D(w, oprand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share alphai: %w", err)
	}
	endFinalShareOLE := time.Now()
	duration = endFinalShareOLE.Sub(startFinalShareOLE)
	log.Println("Calculated final share polynomials for #1 OLE (in s): ", duration.Seconds())

	startFinalShareOLE2 := time.Now()
	delta1i, err := p.evalFinalShare2D(m, oprand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share delta1i: %w", err)
	}
	endFinalShareOLE2 := time.Now()
	duration = endFinalShareOLE2.Sub(startFinalShareOLE2)
	log.Println("Calculated final share polynomials for #2 OLE (in s): ", duration.Seconds())

	endTimeTotal := time.Now()
	duration = endTimeTotal.Sub(startTimeTotal)
	log.Println("Total time for EVAL (in s): ", duration.Seconds())
	return NewBBSPlusTupleGenerator(seed.ski, ai, ei, si, alphai, delta0i, delta1i), nil
}

// PickRandomPolynomials picks c random polynomials of degree N. The last polynomial is not random and always 1.
// This function is intended to be used to generate the random polynomials for calling Eval.
func (p *PCG) PickRandomPolynomials() ([]*poly.Polynomial, error) {
	numElements := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(p.N)), nil)

	polys := make([]*poly.Polynomial, p.c)
	for i := 0; i < p.c-1; i++ {
		nPoly, err := poly.NewRandomPolynomial(p.rng, int(numElements.Int64()))
		if err != nil {
			return nil, err
		}
		polys[i] = nPoly
	}
	// Set last polynomial to 1
	one, err := poly.NewSparse([]*bls12381.Fr{bls12381.NewFr().One()}, []*big.Int{big.NewInt(0)}) // = 1
	if err != nil {
		return nil, err
	}
	polys[p.c-1] = one

	return polys, nil
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
			prod, err := poly.Mul(task.oprand, task.wPoly) // rand[r] and u[r] are swapped in this case
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
				oprandMod, err := task.oprand.Mod(task.div)
				if err != nil {
					results <- evalFinalShareResult{nil, err}
					return
				}

				prod, err := poly.Mul(oprandMod, task.wPoly)
				if err != nil {
					results <- evalFinalShareResult{nil, err}
					return
				}

				remainder, err := prod.Mod(task.div)
				result = evalFinalShareResult{remainder, err}
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

		for i := 0; i < p.n; i++ {
			if i == seedIndex {
				for j := 0; j < p.n; j++ {
					if i != j {
						eval0, err := p.dspfN.FullEvalFast(seedDSPFKeys[i][j][r].Key0)
						if err != nil {
							return nil, err
						}
						eval0Aggregated := aggregateDSPFoutput(eval0) // TODO: Workaround... make this more elegant
						eval0Poly := poly.NewFromFr(eval0Aggregated)
						ur.Add(eval0Poly)

						eval1, err := p.dspfN.FullEvalFast(seedDSPFKeys[j][i][r].Key1)
						if err != nil {
							return nil, err
						}
						eval1Aggregated := aggregateDSPFoutput(eval1) // TODO: Workaround... make this more elegant
						eval1Poly := poly.NewFromFr(eval1Aggregated)
						ur.Add(eval1Poly)
					}
				}
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
			wrs, err := poly.Mul(u[r], v[s]) // u an r are t-sparse -> t*t complexity
			if err != nil {
				return nil, err
			}
			for i := 0; i < p.n; i++ {
				if i == seedIndex {
					for j := 0; j < p.n; j++ {
						if i != j { // Ony cross terms
							eval0, err := p.dspf2N.FullEvalFast(seedDSPFKeys[i][j][r][s].Key0)
							if err != nil {
								return nil, err
							}
							eval0Aggregated := aggregateDSPFoutput(eval0) // TODO: Workaround... make this more elegant
							eval0Poly := poly.NewFromFr(eval0Aggregated)
							wrs.Add(eval0Poly) // N

							eval1, err := p.dspf2N.FullEvalFast(seedDSPFKeys[j][i][r][s].Key1)
							if err != nil {
								return nil, err
							}
							eval1Aggregated := aggregateDSPFoutput(eval1) // TODO: Workaround... make this more elegant
							eval1Poly := poly.NewFromFr(eval1Aggregated)
							wrs.Add(eval1Poly) // N
						}
					}
				}
			}
			w[r][s] = wrs
		}
	}
	return w, nil
}

// embedVOLECorrelations embeds VOLE correlations into DSPF keys.
func (p *PCG) embedVOLECorrelations(omega [][][]*big.Int, beta [][][]*bls12381.Fr, skShares []*bls12381.Fr) ([][][]*DSPFKeyPair, error) {
	U := init3DSliceDspfKey(p.n, p.n, p.c)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.n; j++ {
			if i != j {
				for r := 0; r < p.c; r++ {
					nonZeroElements := scalarMulFr(skShares[j], beta[i][r])
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
