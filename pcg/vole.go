package pcg

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"pcg-master-thesis/pcg/poly"
)

type VOLESeed struct {
	index        int
	ski          *bls12381.Fr
	exponents    SeedExponents
	coefficients SeedCoefficients
	U            [][][]*DSPFKeyPair // U[i][j][r]
}

func (p *PCG) SeedGenVOLE() ([]*VOLESeed, error) {
	_, skShares := getShamirSharedRandomElement(p.rng, p.n, p.n) // TODO: determine how we want to set the threshold for the signature scheme

	aOmega := p.sampleExponents()
	aBeta := p.sampleCoefficients()

	// Embed delta (delta0) correlation (sk*a)
	U, err := p.embedVOLECorrelations(aOmega, aBeta, skShares)
	if err != nil {
		return nil, fmt.Errorf("step 3: failed to generate DSPF keys for first part of delta VOLE correlation (sk * a): %w", err)
	}

	seeds := make([]*VOLESeed, p.n)
	for i := 0; i < p.n; i++ {
		seeds[i] = &VOLESeed{
			index: i,
			ski:   skShares[i],
			exponents: SeedExponents{
				aOmega: aOmega[i],
			},
			coefficients: SeedCoefficients{
				aBeta: aBeta[i],
			},
			U: U,
		}
	}

	return seeds, nil
}

func (p *PCG) EvalVOLE(seed *VOLESeed, rand []*poly.Polynomial, div *poly.Polynomial) (*poly.Polynomial, *poly.Polynomial, error) {

	// 1. Generate polynomials
	fmt.Println("Generating polynomials")
	u, err := p.constructPolys(seed.coefficients.aBeta, seed.exponents.aOmega)
	if err != nil {
		return nil, nil, fmt.Errorf("step 1: failed to generate polynomials for u from aBeta and aOmega: %w", err)
	}

	// 2. Process VOLE (u) with seed / delta0 = ask
	fmt.Println("Processing VOLE")
	utilde, err := p.evalVOLEwithSeed(u, seed.U, seed.index, seed.ski, div)

	deltai, err := p.evalFinalShare(utilde, rand, div)
	if err != nil {
		return nil, nil, fmt.Errorf("step 5: failed to evaluate final share delta0i: %w", err)
	}

	ai, err := p.evalFinalShare(u, rand, div)
	if err != nil {
		return nil, nil, fmt.Errorf("step 5: failed to evaluate final share ai: %w", err)
	}

	return ai, deltai, nil
}
