package pcg

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"math/rand"
	"pcg-master-thesis/dpf"
	"pcg-master-thesis/dspf"
)

type PCG struct {
	lambda int        // lambda is the security parameter used to determine the output length of the underlying PRandomG
	N      int        // N is the domain of the PCG
	n      int        // n is the number of parties participating in this PCG
	c      int        // c is the first security parameter of the Module-LPN assumption
	t      int        // t is the second security parameter of the Module-LPN assumption
	dspfN  *dspf.DSPF // dpfN is the Distributed Sum of Point Function used to construct the PCG with domain N
	dspf2N *dspf.DSPF // dpf2N is the Distributed Sum of Point Function used to construct the PCG with domain 2N
}

// NewPCG creates a new PCG with the given parameters.
// lambda is the security parameter
// N is the domain of the underlying DSPF
// n is the number of parties participating in this PCG
// c is the first security parameter of the Module-LPN assumption
// t is the second security parameter of the Module-LPN assumption
// dpf is the underlying DPF used to construct the DSPF. Its domain is implicitly set to N/2N.
func NewPCG(lambda, N, n, c, t int, dpf dpf.DPF) *PCG {
	return &PCG{
		lambda: lambda,
		N:      N,
		n:      n,
		c:      c,
		t:      t,
		dspfN:  dspf.NewDSPFFactoryWithDomain(dpf, N),
		dspf2N: dspf.NewDSPFFactoryWithDomain(dpf, 2*N),
	}
}

// CentralizedGen generates a seed for each party via a central dealer.
// The goal is to realize a distributed generation.
func (p *PCG) CentralizedGen() ([]*Seed, error) {
	// Notation of the variables analogue to the notation from the formal definition of PCG
	// 1. Generate key shares for each party
	seed, err := bytesToInt64(dpf.RandomSeed(8))
	if err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewSource(seed))
	_, skShares := GetShamirSharedRandomElement(rng, p.n, p.n) // TODO: determine how we want to set the threshold for the signature scheme

	// 2a. Initialize omega, eta, and phi by sampling at random from N
	omega := p.sampleExponents(rng)
	eta := p.sampleExponents(rng)
	phi := p.sampleExponents(rng)

	// 2b. Initialize beta, gamma and epsilon by sampling at random from F_q (bls12381.Fr)
	beta := p.sampleCoefficients(rng)
	gamma := p.sampleCoefficients(rng)
	epsilon := p.sampleCoefficients(rng)

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

// embedVOLECorrelations embeds VOLE correlations into DSPF keys.
func (p *PCG) embedVOLECorrelations(omega [][][]*big.Int, beta [][][]*bls12381.Fr, skShares []*bls12381.Fr) ([][][]*DSPFKeyPair, error) {
	U := init3DSliceDspfKey(p.n, p.n, p.c)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.n; j++ {
			if i != j {
				for r := 0; r < p.c; r++ {
					nonZeroElements := scalarMulFr(skShares[i], beta[i][r])
					key1, key2, err := p.dspfN.Gen(omega[i][r], frSliceToBigIntSlice(nonZeroElements))
					if err != nil {
						return nil, err
					}
					U[i][j][r] = &DSPFKeyPair{key1, key2}
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
					for s := 0; s < p.c; r++ {
						specialPoints := outerSumBigInt(omega[i][r], o[j][s])
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
func (p *PCG) sampleExponents(rng *rand.Rand) [][][]*big.Int {
	exp := init3DSliceBigInt(p.n, p.c, p.t)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.c; j++ {
			vec := make([]*big.Int, p.t)
			for t := range vec {
				vec[t].Rand(rng, big.NewInt(int64(p.N)))
			}
			exp[i][j] = vec
		}
	}
	return exp
}

// sampleCoefficients samples values later used as poly coefficients by picking p.n*p.c random t-vectors from Fq.
func (p *PCG) sampleCoefficients(rng *rand.Rand) [][][]*bls12381.Fr {
	exp := init3DSliceFr(p.n, p.c, p.t)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.c; j++ {
			vec := make([]*bls12381.Fr, p.t)
			for t := range vec {
				randElement, _ := bls12381.NewFr().Rand(rng)
				vec[t].Set(randElement)
			}
			exp[i][j] = vec
		}
	}
	return exp
}
