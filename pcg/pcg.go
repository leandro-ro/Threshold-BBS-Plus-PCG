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
	"time"
)

type PCG struct {
	lambda int        // lambda is the security parameter used to determine the output length of the underlying PRandomG
	N      int        // N is the domain of the PCG. For given N, the PCG is able to generate up to 2^N BBS+ tuples.
	n      int        // n is the number of parties participating in this PCG
	tau    int        // tau is the threshold for the signature scheme (tau-out-of-n setting)
	c      int        // c is the first security parameter of the Module-LPN assumption
	t      int        // t is the second security parameter of the Module-LPN assumption
	dspfN  *dspf.DSPF // dpfN is the Distributed Sum of Point Function used to construct the PCG with domain N
	dspf2N *dspf.DSPF // dpf2N is the Distributed Sum of Point Function used to construct the PCG with domain 2N
	rng    *rand.Rand // rng is the random number generator used to sample the PCG seeds
}

// NewPCG creates a new PCG with the given parameters.
// It uses OptreeDPF as the underlying DPF.
func NewPCG(lambda, N, n, tau, c, t int) (*PCG, error) {
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

	if tau > n {
		return nil, fmt.Errorf("tau must be smaller or equal to n")
	}

	return &PCG{
		lambda: lambda,
		N:      N,
		n:      n,
		tau:    tau,
		c:      c,
		t:      t,
		dspfN:  dspf.NewDSPFFactory(baseDpfDomain),
		dspf2N: dspf.NewDSPFFactory(baseDpfDoubleDomain),
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
	_, skShares := getShamirSharedRandomElement(p.rng, 2, 2) // for testing, we always use 2 out of 2, as we do not interpolate the key shares

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
		keyIndex := i
		if i > 1 {
			keyIndex = 1 // We set the key index for all parties > 1 to 1, as we do not interpolate the key shares for testing purposes TODO: Remove
		}
		seeds[i] = &Seed{
			index: i,
			ski:   skShares[keyIndex],
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
			U: U, // TODO: We are currently sending all U, C and V to each party. This is not necessary, as each party only needs the U, C and V for their index.
			C: C,
			V: V,
		}
	}

	return seeds, nil
}

// EvalCombined evaluates the PCG for an n-out-of-n setting.
// This setting has a better performance than the tau-out-of-n setting (EvalSeparate).
func (p *PCG) EvalCombined(seed *Seed, rand []*poly.Polynomial, div *poly.Polynomial) (*BBSPlusTupleGenerator, error) {
	if p.tau != p.n {
		return nil, fmt.Errorf("EvalCombined can only be used for an n-out-of-n setting")
	}

	startTimeTotal := time.Now()
	if len(rand) != p.c {
		return nil, fmt.Errorf("rand must hold c=%d polynomials but contains %d", p.c, len(rand))
	}
	one, _ := poly.NewSparse([]*bls12381.Fr{bls12381.NewFr().FromBytes(big.NewInt(1).Bytes())}, []*big.Int{big.NewInt(0)}) // = 1
	if !rand[p.c-1].Equal(one) {
		return nil, fmt.Errorf("rand must be a slice of polynomials with polynomial of the the last index rand[c-1] equal to 1")
	}

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
	startVole := time.Now()
	utilde, err := p.evalVOLEwithSeed(u, seed.ski, seed.U, seed.index, div)
	if err != nil {
		return nil, fmt.Errorf("step 2: failed to evaluate VOLE (utilde): %w", err)
	}
	endVole := time.Now()
	duration = endVole.Sub(startVole)
	log.Println("Processed VOLE (in s): ", duration.Seconds())

	// 3. Process first OLE correlation (u, k) with seed / alpha = as
	startOle := time.Now()
	w, err := p.evalOLEwithSeed(u, k, seed.C, seed.index, div)
	if err != nil {
		return nil, fmt.Errorf("step 3: failed to evaluate OLE (w): %w", err)
	}
	endOle := time.Now()
	duration = endOle.Sub(startOle)
	log.Println("Processed #1 OLE (in s): ", duration.Seconds())

	// 4. Process second OLE correlation (u, v) with seed /  delta1 = ae
	startOle2 := time.Now()
	m, err := p.evalOLEwithSeed(u, v, seed.V, seed.index, div)
	if err != nil {
		return nil, fmt.Errorf("step 4: failed to evaluate OLE (m): %w", err)
	}
	endOle2 := time.Now()
	duration = endOle2.Sub(startOle2)
	log.Println("Processed #2 OLE (in s): ", duration.Seconds())

	// 5. Calculate final shares
	startFinalShareAi := time.Now()
	ai, err := p.evalFinalShare(u, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ai: %w", err)
	}
	endFinalShareAi := time.Now()
	duration = endFinalShareAi.Sub(startFinalShareAi)
	log.Println("Calculated final share polynomials for ai (in s): ", duration.Seconds())

	startFinalShareEi := time.Now()
	ei, err := p.evalFinalShare(v, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ei: %w", err)
	}
	endFinalShareEi := time.Now()
	duration = endFinalShareEi.Sub(startFinalShareEi)
	log.Println("Calculated final share polynomials for ei (in s): ", duration.Seconds())

	startFinalShareSi := time.Now()
	si, err := p.evalFinalShare(k, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ki: %w", err)
	}
	endFinalShareSi := time.Now()
	duration = endFinalShareSi.Sub(startFinalShareSi)
	log.Println("Calculated final share polynomials for si (in s): ", duration.Seconds())

	startFinalShareVOLE := time.Now()
	delta0i, err := p.evalFinalShare(utilde, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share delta0i: %w", err)
	}
	endFinalShareVOLE := time.Now()
	duration = endFinalShareVOLE.Sub(startFinalShareVOLE)
	log.Println("Calculated final share polynomials for VOLE (delta0i) (in s): ", duration.Seconds())

	oprand, err := outerProductPoly(rand, rand)
	if err != nil {
		return nil, err
	}

	startFinalShareOLE := time.Now()
	alphai, err := p.evalFinalShare2D(w, oprand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share alphai: %w", err)
	}
	endFinalShareOLE := time.Now()
	duration = endFinalShareOLE.Sub(startFinalShareOLE)
	log.Println("Calculated final share polynomials for #1 OLE (alphai) (in s): ", duration.Seconds())

	startFinalShareOLE2 := time.Now()
	delta1i, err := p.evalFinalShare2D(m, oprand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share delta1i: %w", err)
	}
	endFinalShareOLE2 := time.Now()
	duration = endFinalShareOLE2.Sub(startFinalShareOLE2)
	log.Println("Calculated final share polynomials for #2 OLE (delta1i) (in s): ", duration.Seconds())

	endTimeTotal := time.Now()
	duration = endTimeTotal.Sub(startTimeTotal)
	log.Println("Total time for EVAL (in s): ", duration.Seconds())

	return NewBBSPlusTupleGenerator(seed.ski, ai, ei, si, alphai, delta0i, delta1i), nil
}

// EvalSeparate evaluates the PCG for a tau-out-of-n setting.
// This setting has a worse performance than the n-out-of-n setting (EvalCombined).
func (p *PCG) EvalSeparate(seed *Seed, rand []*poly.Polynomial, div *poly.Polynomial) (*SeparateBBSPlusTupleGenerator, error) {
	startTimeTotal := time.Now()

	if len(rand) != p.c {
		return nil, fmt.Errorf("rand must hold c=%d polynomials but contains %d", p.c, len(rand))
	}
	one, _ := poly.NewSparse([]*bls12381.Fr{bls12381.NewFr().FromBytes(big.NewInt(1).Bytes())}, []*big.Int{big.NewInt(0)}) // = 1
	if !rand[p.c-1].Equal(one) {
		return nil, fmt.Errorf("rand must be a slice of polynomials with polynomial of the the last index rand[c-1] equal to 1")
	}

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
	startVole := time.Now()
	utilde, err := p.evalVOLEwithSeedSeparate(seed.U, seed.index) // utilde[seedIndex] is nil!
	if err != nil {
		return nil, fmt.Errorf("step 2: failed to evaluate VOLE (utilde): %w", err)
	}
	usk := make([]*poly.Polynomial, p.c) // TODO: Can we actually do this here? Because of sk interpolation...
	for r := 0; r < p.c; r++ {
		usk[r] = u[r].DeepCopy()
		usk[r].MulByConstant(seed.ski)
	}
	endVole := time.Now()
	duration = endVole.Sub(startVole)
	log.Println("Processed VOLE (in s): ", duration.Seconds())

	// 3. Process first OLE correlation (u, k) with seed / alpha = as
	startOle := time.Now()
	w, uk, err := p.evalOLEwithSeedSeparate(u, k, seed.C, seed.index) // w[seedIndex] is nil!
	if err != nil {
		return nil, fmt.Errorf("step 3: failed to evaluate OLE (w): %w", err)
	}
	endOle := time.Now()
	duration = endOle.Sub(startOle)
	log.Println("Processed #1 OLE (in s): ", duration.Seconds())

	// 4. Process second OLE correlation (u, v) with seed /  delta1 = ae
	startOle2 := time.Now()
	m, uv, err := p.evalOLEwithSeedSeparate(u, v, seed.V, seed.index) // m[seedIndex] is nil!
	if err != nil {
		return nil, fmt.Errorf("step 4: failed to evaluate OLE (m): %w", err)
	}
	endOle2 := time.Now()
	duration = endOle2.Sub(startOle2)
	log.Println("Processed #2 OLE (in s): ", duration.Seconds())

	// 5. Calculate final shares
	startFinalShareAi := time.Now()
	ai, err := p.evalFinalShare(u, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ai: %w", err)
	}
	endFinalShareAi := time.Now()
	duration = endFinalShareAi.Sub(startFinalShareAi)
	log.Println("Calculated final share polynomials for ai (in s): ", duration.Seconds())

	startFinalShareEi := time.Now()
	ei, err := p.evalFinalShare(v, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ei: %w", err)
	}
	endFinalShareEi := time.Now()
	duration = endFinalShareEi.Sub(startFinalShareEi)
	log.Println("Calculated final share polynomials for ei (in s): ", duration.Seconds())

	startFinalShareSi := time.Now()
	si, err := p.evalFinalShare(k, rand, div)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share ki: %w", err)
	}
	endFinalShareSi := time.Now()
	duration = endFinalShareSi.Sub(startFinalShareSi)
	log.Println("Calculated final share polynomials for si (in s): ", duration.Seconds())

	startFinalShareVOLE := time.Now()
	delta0i := make([][]*poly.Polynomial, p.n) // delta0i[seedIndex] is nil!
	for j := 0; j < p.n; j++ {
		if j != seed.index { // only for counterparties
			delta0i[j] = make([]*poly.Polynomial, 2)
			forwardShareJ, err := p.evalFinalShare(utilde[j][forwardDirection], rand, div)
			if err != nil {
				return nil, fmt.Errorf("step 5: failed to evaluate final share delta0i: %w", err)
			}
			delta0i[j][forwardDirection] = poly.NewEmpty()
			delta0i[j][forwardDirection].Set(forwardShareJ)

			backwardShareJ, err := p.evalFinalShare(utilde[j][backwardDirection], rand, div)
			if err != nil {
				return nil, fmt.Errorf("step 5: failed to evaluate final share delta0i: %w", err)
			}
			delta0i[j][backwardDirection] = poly.NewEmpty()
			delta0i[j][backwardDirection].Set(backwardShareJ)
		}
	}
	uskEval, err := p.evalFinalShare(usk, rand, div) // Eval usk (we count this to delta0i)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share usk: %w", err)
	}
	endFinalShareVOLE := time.Now()
	duration = endFinalShareVOLE.Sub(startFinalShareVOLE)
	log.Println("Calculated final share polynomials for VOLE (delta0i) (in s): ", duration.Seconds())

	oprand, err := outerProductPoly(rand, rand)
	if err != nil {
		return nil, err
	}

	startFinalShareOLE := time.Now()
	alphai := make([]*poly.Polynomial, p.n) // alphai[seedIndex] is nil!
	for j := 0; j < p.n; j++ {
		if j != seed.index { // only for counterparties
			alphai[j], err = p.evalFinalShare2D(w[j], oprand, div)
			if err != nil {
				return nil, fmt.Errorf("step 5: failed to evaluate final share alphai: %w", err)
			}
		}
	}
	ukEval, err := p.evalFinalShare2D(uk, oprand, div) // Eval uk (we count this to alphai)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share uk: %w", err)
	}
	endFinalShareOLE := time.Now()
	duration = endFinalShareOLE.Sub(startFinalShareOLE)
	log.Println("Calculated final share polynomials for #1 OLE (alphai) (in s): ", duration.Seconds())

	startFinalShareOLE2 := time.Now()
	delta1i := make([]*poly.Polynomial, p.n) // delta1i[seedIndex] is nil!
	for j := 0; j < p.n; j++ {
		if j != seed.index { // only for counterparties
			delta1i[j], err = p.evalFinalShare2D(m[j], oprand, div)
			if err != nil {
				return nil, fmt.Errorf("step 5: failed to evaluate final share delta1i: %w", err)
			}
		}
	}
	uvEval, err := p.evalFinalShare2D(uv, oprand, div) // Eval uv (we count this to delta1i)
	if err != nil {
		return nil, fmt.Errorf("step 5: failed to evaluate final share uv: %w", err)
	}
	endFinalShareOLE2 := time.Now()
	duration = endFinalShareOLE2.Sub(startFinalShareOLE2)
	log.Println("Calculated final share polynomials for #2 OLE (delta1i) (in s): ", duration.Seconds())

	endTimeTotal := time.Now()
	duration = endTimeTotal.Sub(startTimeTotal)
	log.Println("Total time for EVAL (in s): ", duration.Seconds())

	return NewSeparateBBSPlusTupleGenerator(uskEval, ukEval, uvEval, seed.ski, ai, ei, si, delta0i, alphai, delta1i), nil
}

// PickRandomPolynomials picks c random polynomials of degree N. The last polynomial is not random and always 1.
// This function is intended to be used to generate the random polynomials for calling EvalCombined.
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
