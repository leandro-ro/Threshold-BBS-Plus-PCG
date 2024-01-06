package pcg

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"math/rand"
	"pcg-master-thesis/dpf"
	optreedpf "pcg-master-thesis/dpf/2018_boyle_optimization"
	"pcg-master-thesis/dspf"
	"pcg-master-thesis/pcg/poly"
	"sort"
)

type PCG struct {
	lambda int        // lambda is the security parameter used to determine the output length of the underlying PRandomG
	N      int        // N is the domain of the PCG
	n      int        // n is the number of parties participating in this PCG
	c      int        // c is the first security parameter of the Module-LPN assumption
	t      int        // t is the second security parameter of the Module-LPN assumption
	dspfN  *dspf.DSPF // dpfN is the Distributed Sum of Point Function used to construct the PCG with domain N
	dspf2N *dspf.DSPF // dpf2N is the Distributed Sum of Point Function used to construct the PCG with domain 2N
	rng    *rand.Rand // rng is the random number generator used to sample the PCG seeds
}

// NewPCG creates a new PCG with the given parameters.
// lambda is the security parameter
// N is the domain determines the amount of presignatures that can be generated
// n is the number of parties participating in this PCG
// c is the first security parameter of the Module-LPN assumption
// t is the second security parameter of the Module-LPN assumption
func NewPCG(lambda, N, n, c, t int) (*PCG, error) {
	seed, _ := bytesToInt64(dpf.RandomSeed(8))
	rng := rand.New(rand.NewSource(seed)) // TODO: Swap this out for a secure PRG

	// TODO: Make base DPF exchangeable
	baseDpfN, err := optreedpf.InitFactory(lambda, N)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize base DPF with domain N: %w", err)
	}
	baseDpf2N, err := optreedpf.InitFactory(lambda, N+1)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize base DPF with domain 2N: %w", err)
	}

	return &PCG{
		lambda: lambda,
		N:      N,
		n:      n,
		c:      c,
		t:      t,
		dspfN:  dspf.NewDSPFFactoryWithDomain(baseDpfN, N),
		dspf2N: dspf.NewDSPFFactoryWithDomain(baseDpf2N, N+1),
		rng:    rng,
	}, nil
}

// TrustedSeedGen generates a seed for each party via a central dealer.
// The goal is to realize a distributed generation.
func (p *PCG) TrustedSeedGen() ([]*Seed, error) {
	// Notation of the variables analogue to the notation from the formal definition of PCG
	// 1. Generate key shares for each party
	_, skShares := getShamirSharedRandomElement(p.rng, p.n, p.n) // TODO: determine how we want to set the threshold for the signature scheme

	// 2a. Initialize omega, eta, and phi by sampling at random from N
	omega := p.sampleExponents()
	eta := p.sampleExponents()
	phi := p.sampleExponents()

	// 2b. Initialize beta, gamma and epsilon by sampling at random from F_q (bls12381.Fr)
	beta := p.sampleCoefficients()
	gamma := p.sampleCoefficients()
	epsilon := p.sampleCoefficients()

	// 3. Embed first part of delta correlation (sk*a)
	U, err := p.embedVOLECorrelations(omega, beta, skShares)
	if err != nil {
		return nil, fmt.Errorf("step 3: failed to generate DSPF keys for first part of delta VOLE correlation (sk * a): %w", err)
	}

	// 4a. Embed alpha correlation (a*s)
	C, err := p.embedOLECorrelations(omega, eta, beta, gamma)
	if err != nil {
		return nil, fmt.Errorf("step 4: failed to generate DSPF keys for alpha OLE correlation (a * s): %w", err)
	}

	// 4b. Embed second part of delta correlation (a*e)
	V, err := p.embedOLECorrelations(omega, phi, beta, epsilon)
	if err != nil {
		return nil, fmt.Errorf("step 4: failed to generate DSPF keys for second part of delta OLE correlation (a * e): %w", err)
	}

	// 5. Generate seed for each party
	seeds := make([]*Seed, p.n)
	for i := 0; i < p.n; i++ {
		seeds[i] = &Seed{
			index: i,
			ski:   skShares[i],
			exponents: SeedExponents{
				omega: omega[i],
				eta:   eta[i],
				phi:   phi[i],
			},
			coefficients: SeedCoefficients{
				beta:    beta[i],
				gamma:   gamma[i],
				epsilon: epsilon[i],
			},
			U: U,
			C: C,
			V: V,
		}
	}

	return seeds, nil
}

// Eval evaluates the PCG for the given seed based on a c random polynomials.
func (p *PCG) Eval(seed *Seed, rand []*poly.Polynomial, div *poly.Polynomial) (*BBSPlusTupleGenerator, error) {
	if len(rand) != p.c {
		return nil, fmt.Errorf("rand must hold c=%d polynomials but contains %d", p.c, len(rand))
	}
	one, _ := poly.NewSparse([]*bls12381.Fr{bls12381.NewFr().FromBytes(big.NewInt(1).Bytes())}, []*big.Int{big.NewInt(0)}) // = 1
	if !rand[p.c-1].Equal(one) {
		return nil, fmt.Errorf("rand must be a slice of polynomials with polynomial of the the last index rand[c-1] equal to 1")
	}

	// 1. Generate polynomials
	fmt.Println("Generating polynomials")
	u, err := p.constructPolys(seed.coefficients.beta, seed.exponents.omega)
	if err != nil {
		return nil, fmt.Errorf("step 1: failed to generate polynomials for u from beta and omega: %w", err)
	}
	v, err := p.constructPolys(seed.coefficients.gamma, seed.exponents.eta)
	if err != nil {
		return nil, fmt.Errorf("step 1: failed to generate polynomials for v from gamma and eta: %w", err)
	}
	k, err := p.constructPolys(seed.coefficients.epsilon, seed.exponents.phi)
	if err != nil {
		return nil, fmt.Errorf("step 1: failed to generate polynomials for k from epsilon and phi: %w", err)
	}

	// 2. Process VOLE (u) with seed
	fmt.Println("Processing VOLE")
	utilde, err := p.evalVOLEwithSeed(u, seed, div)
	if err != nil {
		return nil, fmt.Errorf("step 2: failed to evaluate VOLE (utilde): %w", err)
	}
	// 3. Process first OLE correlation (u, v) with seed
	fmt.Println("Processing #1 OLE")
	w, err := p.evalOLEwithSeed(u, v, seed, div)
	if err != nil {
		return nil, fmt.Errorf("step 3: failed to evaluate OLE (w): %w", err)
	}
	// 4. Process second OLE correlation (u, k) with seed
	fmt.Println("Processing #2 OLE")
	m, err := p.evalOLEwithSeed(u, k, seed, div)
	if err != nil {
		return nil, fmt.Errorf("step 4: failed to evaluate OLE (m): %w", err)
	}

	// Calculate divisor polynomial (for efficient modulus we use a cyclotomic polynomial)
	//twoPowN := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(p.N)), nil)
	//div, err := poly.NewCyclotomicPolynomial(twoPowN) // div = x^N^2 + neg(1)
	//if err != nil {
	//	return nil, err
	//}

	// 5. Calculate final shares
	fmt.Println("Calculating final shares")
	ai, err := p.evalFinalShare(u, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ai: %w", err)
	}
	si, err := p.evalFinalShare(v, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share si: %w", err)
	}
	ei, err := p.evalFinalShare(k, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ei: %w", err)
	}
	delta1i, err := p.evalFinalShare(utilde, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share delta1i: %w", err)
	}

	oprand, err := outerProductPoly(rand, rand) // This is probably the only time FFT is used for multiplication
	if err != nil {
		return nil, err
	}

	fmt.Println("Calculating final shares 2D")
	alphai, err := p.evalFinalShare2D(w, oprand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share alphai: %w", err)
	}
	delta0i, err := p.evalFinalShare2D(m, oprand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share delta1i: %w", err)
	}

	return NewBBSPlusTupleGenerator(seed.ski, ai, si, ei, alphai, delta0i, delta1i), nil
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

// Ring defines the ring we work in.
type Ring struct {
	Div   *poly.Polynomial
	Roots []*bls12381.Fr
}

// Uses cyclotomic polynomials to define the ring.
func (p *PCG) GetRing() (*Ring, error) {
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

	roots := make([]*bls12381.Fr, twoPowN.Int64())
	for i := 0; i < int(twoPowN.Int64()); i++ {
		val := new(big.Int).Exp(powerIteratorBase, big.NewInt(int64(i+1)), groupOrder)
		roots[i] = bls12381.NewFr().FromBytes(val.Bytes())
	}

	div, err := poly.NewCyclotomicPolynomial(twoPowN) // div = x^N^2 + neg(1)
	if err != nil {
		return nil, err
	}

	return &Ring{div, roots}, nil
}

// evalFinalShare evaluates the final share of the PCG for the given polynomial.
// This function effectively calculates the inner product between the given polynomial and the random polynomials in div.
func (p *PCG) evalFinalShare(u, rand []*poly.Polynomial, div *poly.Polynomial) (*poly.Polynomial, error) {
	ai := poly.NewEmpty()
	for j := 0; j < p.c-1; j++ {
		prod, err := poly.Mul(rand[j], u[j])
		if err != nil {
			return nil, err
		}
		remainder, err := prod.Mod(div)
		if err != nil {
			return nil, err
		}
		ai.Add(remainder)
	}
	finalValU, err := u[p.c-1].Mod(div)
	if err != nil {
		return nil, err
	}
	ai.Add(finalValU) // rand[c-1] is always 1, hence instead of multiplying we can just add
	return ai, nil
}

// evalFinalShare2D evaluates the final share of the PCG for the given polynomial.
// This function effectively calculates the inner product between the given polynomial and the random polynomials in div.
func (p *PCG) evalFinalShare2D(w [][]*poly.Polynomial, oprand []*poly.Polynomial, div *poly.Polynomial) (*poly.Polynomial, error) {
	alphai := poly.NewEmpty()
	for j := 0; j < p.c-1; j++ {
		for k := 0; k < p.c-1; k++ {
			prod, err := poly.Mul(oprand[j*p.c+k], w[j][k])
			if err != nil {
				return nil, err
			}
			remainder, err := prod.Mod(div)
			if err != nil {
				return nil, err
			}
			alphai.Add(remainder)
		}
	}
	finalValW, err := w[p.c-1][p.c-1].Mod(div)
	if err != nil {
		return nil, err
	}
	alphai.Add(finalValW) // oprand[c*c-1] is always 1, we can just add w[c-1][c-1] it
	return alphai, nil
}

// evalVOLEwithSeed evaluates the VOLE correlation with the given seed.
func (p *PCG) evalVOLEwithSeed(u []*poly.Polynomial, seed *Seed, div *poly.Polynomial) ([]*poly.Polynomial, error) {
	utilde := make([]*poly.Polynomial, p.c)
	for r := 0; r < p.c; r++ {
		ur := u[r].DeepCopy()      // We need unmodified u[r] later on, so we copy it
		ur.MulByConstant(seed.ski) // u[r] * sk[i]
		for i := 0; i < p.n; i++ { // Ony cross terms
			for j := 0; j < p.n; j++ {
				if i != j {
					eval0, err := p.dspfN.FullEvalFast(seed.U[i][j][r].Key0)
					if err != nil {
						return nil, err
					}
					eval0Aggregated := aggregateDSPFoutput(eval0) // TODO: Workaround... make this more elegant
					eval0Poly := poly.NewFromFr(eval0Aggregated)
					ur.Add(eval0Poly)

					ur, err = ur.Mod(div)
					if err != nil {
						return nil, err
					}

					eval1, err := p.dspfN.FullEvalFast(seed.U[i][j][r].Key1)
					if err != nil {
						return nil, err
					}
					eval1Aggregated := aggregateDSPFoutput(eval1) // TODO: Workaround... make this more elegant
					eval1Poly := poly.NewFromFr(eval1Aggregated)
					ur.Add(eval1Poly)

					ur, err = ur.Mod(div)
					if err != nil {
						return nil, err
					}
				}
			}
		}
		utilde[r] = ur
	}
	return utilde, nil
}

// evalOLEwithSeed evaluates the OLE correlation with the given seed.
func (p *PCG) evalOLEwithSeed(u, v []*poly.Polynomial, seed *Seed, div *poly.Polynomial) ([][]*poly.Polynomial, error) {
	w := make([][]*poly.Polynomial, p.c)
	for r := 0; r < p.c; r++ {
		w[r] = make([]*poly.Polynomial, p.c)
		for s := 0; s < p.c; s++ {
			wrs, err := poly.Mul(u[r], v[s])
			if err != nil {
				return nil, err
			}
			for i := 0; i < p.n; i++ {
				for j := 0; j < p.n; j++ {
					if i != j { // Ony cross terms
						eval0, err := p.dspf2N.FullEvalFast(seed.C[i][j][r][s].Key0)
						if err != nil {
							return nil, err
						}
						eval0Aggregated := aggregateDSPFoutput(eval0) // TODO: Workaround... make this more elegant
						eval0Poly := poly.NewFromFr(eval0Aggregated)
						wrs.Add(eval0Poly)

						wrs, err = wrs.Mod(div)
						if err != nil {
							return nil, err
						}

						eval1, err := p.dspf2N.FullEvalFast(seed.C[i][j][r][s].Key1)
						if err != nil {
							return nil, err
						}
						eval1Aggregated := aggregateDSPFoutput(eval1) // TODO: Workaround... make this more elegant
						eval1Poly := poly.NewFromFr(eval1Aggregated)
						wrs.Add(eval1Poly)

						wrs, err = wrs.Mod(div)
						if err != nil {
							return nil, err
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
						specialPoints := outerSumBigInt(omega[i][r], o[j][s]) // We can only change o, as omega is used in the other OLE correlation
						// TODO: Find a fix for this!
						if hasDuplicates(specialPoints) {
							return nil, fmt.Errorf("special points contain duplicates")
						}
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

type SampledExponents struct {
	values [][][]*big.Int
}

func (s *SampledExponents) DeepCopy() *SampledExponents {
	res := init3DSliceBigInt(len(s.values), len(s.values[0]), len(s.values[0][0]))
	for i := 0; i < len(s.values); i++ {
		for j := 0; j < len(s.values[0]); j++ {
			for k := 0; k < len(s.values[0][0]); k++ {
				val := new(big.Int).SetBytes(s.values[i][j][k].Bytes())
				res[i][j][k] = val
			}
		}
	}
	return &SampledExponents{res}
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
