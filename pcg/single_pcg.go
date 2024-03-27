package pcg

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"log"
	"math/big"
	"pcg-bbs-plus/pcg/poly"
	"time"
)

// GenSingleOlePCG generates PCG seeds embedding a single OLE.
// This is intended for benchmarking purposes and can only be used with two parties (p.n=2).
func (p *PCG) genSingleOlePCG() ([]*oleSeed, error) {
	if p.n != 2 {
		return nil, fmt.Errorf("genSingleOlePCG can only be used with two parties")
	}
	aOmega := p.sampleExponents()
	aBeta := p.sampleCoefficients()

	V := make([][]*DSPFKeyPair, p.c)
	for i := range V {
		V[i] = make([]*DSPFKeyPair, p.c)
		for j := range V[i] {
			V[i][j] = new(DSPFKeyPair)
		}
	}
	for r := 0; r < p.c; r++ {
		for s := 0; s < p.c; s++ {
			specialPoints := outerSumBigInt(aOmega[0][r], aOmega[1][s])
			nonZeroElements := outerProductFr(aBeta[0][r], aBeta[1][s])

			key1, key2, err := p.dspf2N.Gen(specialPoints, frSliceToBigIntSlice(nonZeroElements))
			if err != nil {
				return nil, err
			}

			V[r][s] = &DSPFKeyPair{key1, key2}
		}
	}

	seeds := make([]*oleSeed, p.n)
	for i := 0; i < p.n; i++ {
		seeds[i] = &oleSeed{
			index: i,
			exponents: seedExponents{
				aOmega: aOmega[i],
			},
			coefficients: seedCoefficients{
				aBeta: aBeta[i],
			},
			V: V,
		}
	}
	return seeds, nil
}

// evalSingleOle evaluates a single OLE seed.
// This is intended for benchmarking purposes and can only be used with two parties (p.n=2).
func (p *PCG) evalSingleOle(seed *oleSeed, rand []*poly.Polynomial, div *poly.Polynomial) (*poly.Polynomial, *poly.Polynomial, error) {
	startTimerSetup := time.Now()
	if p.n != 2 {
		return nil, nil, fmt.Errorf("evalSingleOle can only be used with two parties")
	}

	if len(rand) != p.c {
		return nil, nil, fmt.Errorf("rand must hold c=%d polynomials but contains %d", p.c, len(rand))
	}
	one, _ := poly.NewSparse([]*bls12381.Fr{bls12381.NewFr().FromBytes(big.NewInt(1).Bytes())}, []*big.Int{big.NewInt(0)}) // = 1
	if !rand[p.c-1].Equal(one) {
		return nil, nil, fmt.Errorf("rand must be a slice of polynomials with polynomial of the the last index rand[c-1] equal to 1")
	}

	e, err := p.constructPolys(seed.coefficients.aBeta, seed.exponents.aOmega)
	if err != nil {
		return nil, nil, fmt.Errorf("step 1: failed to generate polynomials for u from aBeta and aOmega: %w", err)
	}
	endTimerSetup := time.Now()
	log.Println("Time for setup: ", endTimerSetup.Sub(startTimerSetup).Seconds())

	startTimerFullEval := time.Now()
	w := make([][]*poly.Polynomial, p.c)
	for i := 0; i < p.c; i++ {
		w[i] = make([]*poly.Polynomial, p.c)
		for j := 0; j < p.c; j++ {
			key := seed.V[i][j].Key0
			if seed.index == 1 {
				key = seed.V[i][j].Key1
			}

			eval0, err := p.dspf2N.FullEvalFastAggregated(key)

			if err != nil {
				return nil, nil, err
			}
			w[i][j] = new(poly.Polynomial)
			w[i][j].Set(poly.NewFromFr(eval0))
		}
	}
	endTimerFullEval := time.Now()
	log.Println("Time for full eval: ", endTimerFullEval.Sub(startTimerFullEval).Seconds())

	startTimerRingElement := time.Now()
	// Evaluate the polynomials
	ei, err := p.evalFinalShare(e, rand, div)
	if err != nil {
		return nil, nil, err
	}
	oprand, err := outerProductPoly(rand, rand)
	if err != nil {
		return nil, nil, err
	}
	wi, err := p.evalFinalShare2D(w, oprand, div)
	if err != nil {
		return nil, nil, err
	}
	endTimerRingElement := time.Now()
	log.Println("Time for ring element: ", endTimerRingElement.Sub(startTimerRingElement).Seconds())

	return ei, wi, nil
}

// genSingleVolePCG generates PCG seeds embedding a single VOLE.
// This is intended for benchmarking purposes and can only be used with two parties (p.n=2).
func (p *PCG) genSingleVolePCG() ([]*voleSeed, error) {
	if p.n != 2 {
		return nil, fmt.Errorf("genSingleVolePCG can only be used with two parties")
	}
	aOmega := p.sampleExponents()   // we only use aOmega[0]
	aBeta := p.sampleCoefficients() // we only use aBeta[0]

	_, skShares := getShamirSharedRandomElement(p.rng, 2, 2) // we only use skShares[1]

	V := make([]*DSPFKeyPair, p.c)
	for i := range V {
		V[i] = new(DSPFKeyPair)
	}
	for r := 0; r < p.c; r++ {
		specialPoints := aOmega[0][r]
		nonZeroElements := scalarMulFr(skShares[1], aBeta[0][r])

		key1, key2, err := p.dspfN.Gen(specialPoints, frSliceToBigIntSlice(nonZeroElements))
		if err != nil {
			return nil, err
		}

		V[r] = &DSPFKeyPair{key1, key2}
	}

	seeds := make([]*voleSeed, p.n)
	for i := 0; i < p.n; i++ {
		seeds[i] = &voleSeed{
			index:    i,
			constant: skShares[1],
			exponents: seedExponents{
				aOmega: aOmega[i],
			},
			coefficients: seedCoefficients{
				aBeta: aBeta[i],
			},
			V: V,
		}
	}
	return seeds, nil
}

// evalSingleVole evaluates a single VOLE seed.
// This is intended for benchmarking purposes and can only be used with two parties (p.n=2).
func (p *PCG) evalSingleVole(seed *voleSeed, rand []*poly.Polynomial, div *poly.Polynomial) (*poly.Polynomial, *poly.Polynomial, error) {
	startTimerSetup := time.Now()
	if p.n != 2 {
		return nil, nil, fmt.Errorf("evalSingleVole can only be used with two parties")
	}

	if len(rand) != p.c {
		return nil, nil, fmt.Errorf("rand must hold c=%d polynomials but contains %d", p.c, len(rand))
	}
	one, _ := poly.NewSparse([]*bls12381.Fr{bls12381.NewFr().FromBytes(big.NewInt(1).Bytes())}, []*big.Int{big.NewInt(0)}) // = 1
	if !rand[p.c-1].Equal(one) {
		return nil, nil, fmt.Errorf("rand must be a slice of polynomials with polynomial of the the last index rand[c-1] equal to 1")
	}

	e, err := p.constructPolys(seed.coefficients.aBeta, seed.exponents.aOmega)
	if err != nil {
		return nil, nil, fmt.Errorf("step 1: failed to generate polynomials for u from aBeta and aOmega: %w", err)
	}
	endTimerSetup := time.Now()
	log.Println("Time for setup: ", endTimerSetup.Sub(startTimerSetup).Seconds())

	startTimerFullEval := time.Now()
	w := make([]*poly.Polynomial, p.c)
	for i := 0; i < p.c; i++ {
		w[i] = new(poly.Polynomial)
		key := seed.V[i].Key0
		if seed.index == 1 {
			key = seed.V[i].Key1
		}

		eval0, err := p.dspfN.FullEvalFastAggregated(key)

		if err != nil {
			return nil, nil, err
		}
		w[i] = new(poly.Polynomial)
		w[i].Set(poly.NewFromFr(eval0))
	}
	endTimerFullEval := time.Now()
	log.Println("Time for full eval: ", endTimerFullEval.Sub(startTimerFullEval).Seconds())

	startTimerRingElement := time.Now()
	// Evaluate the polynomials
	ei, err := p.evalFinalShare(e, rand, div)
	if err != nil {
		return nil, nil, err
	}
	wi, err := p.evalFinalShare(w, rand, div)
	if err != nil {
		return nil, nil, err
	}
	endTimerRingElement := time.Now()
	log.Println("Time for ring element: ", endTimerRingElement.Sub(startTimerRingElement).Seconds())

	if seed.index == 0 {
		return ei, wi, nil
	} else {
		sliceConstant := []*bls12381.Fr{seed.constant}
		constPoly := poly.NewFromFr(sliceConstant) // Poly only with the constant value
		return constPoly, wi, nil
	}

}
