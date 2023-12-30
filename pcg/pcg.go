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
// N is the domain of the underlying DSPF. Note that this sets the max bit-length of the special elements.
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

// CentralizedGen generates a seed for each party via a central dealer.
// The goal is to realize a distributed generation.
func (p *PCG) CentralizedGen() ([]*Seed, error) {
	// Notation of the variables analogue to the notation from the formal definition of PCG
	// 1. Generate key shares for each party
	_, skShares := GetShamirSharedRandomElement(p.rng, p.n, p.n) // TODO: determine how we want to set the threshold for the signature scheme

	// 2a. Initialize omega, eta, and phi by sampling at random from N
	// TODO: The matrix resulting from the outer sum between omega/eta & omega/phi must result in a matrix with unique elements. This is not guaranteed by the current implementation.
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
				omega: omega.values[i],
				eta:   eta.values[i],
				phi:   phi.values[i],
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
func (p *PCG) Eval(seed *Seed, rand []*poly.Polynomial) (*GeneratedTuples, error) {
	if len(rand) != p.c {
		return nil, fmt.Errorf("rand must hold c=%d polynomials but contains %d", p.c, len(rand))
	}
	one, _ := poly.NewSparse([]*bls12381.Fr{bls12381.NewFr().One()}, []*big.Int{big.NewInt(0)}) // = 1
	if !rand[p.c-1].Equal(one) {
		return nil, fmt.Errorf("rand must be a slice of polynomials with polynomial of the the last index rand[c-1] equal to 1")
	}

	// 1. Generate polynomials
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

	// 2. Process VOLE seed
	utilde := make([]*poly.Polynomial, p.c)
	for r := 0; r < p.c; r++ {
		ur := u[r].Copy()          // We need unmodified u[r] later on, so we copy it
		ur.MulByConstant(seed.ski) // u[r] * sk[i]
		for i := 0; i < p.n; i++ { // Ony cross terms
			for j := 0; j < p.n; j++ {
				if i != j {
					fmt.Println("VOLE progress: ", i, j, r, "of", p.n, p.n, p.c)
					feval0, err := p.dspfN.FullEvalFast(seed.U[i][j][r].Key0)
					if err != nil {
						return nil, err
					}
					feval1, err := p.dspfN.FullEvalFast(seed.U[i][j][r].Key1)
					if err != nil {
						return nil, err
					}

					res, err := p.dspfN.CombineMultipleResults(feval0, feval1)
					if len(res) != p.t {
						return nil, fmt.Errorf("step 2: length of VOLE DSPF FullEval is %d but is expected to be t=%d", len(res), p.t)
					}

					err = ur.SparseBigAdd(res)
					if err != nil {
						return nil, err
					}
				}
			}
		}
		utilde[r] = ur
	}

	// 3. Process first OLE seed
	w := make([][]*poly.Polynomial, p.c)
	for r := 0; r < p.c; r++ {
		w[r] = make([]*poly.Polynomial, p.c)
		for s := 0; s < p.c; s++ {
			ur := u[r].Copy()      // We need unmodified u[r] later on, so we copy it
			vs := v[s].Copy()      // We need unmodified v[s] later on, so we copy it
			wrs, err := ur.Mul(vs) // u[r] * v[s]
			if err != nil {
				return nil, err
			}
			for i := 0; i < p.n; i++ {
				for j := 0; j < p.n; j++ {
					if i != j { // Ony cross terms
						fmt.Println("OLE #1 progress: ", i, j, r, "of", p.n, p.n, p.c)
						feval0, err := p.dspf2N.FullEvalFast(seed.C[i][j][r][s].Key0)
						if err != nil {
							return nil, err
						}
						feval1, err := p.dspf2N.FullEvalFast(seed.C[i][j][r][s].Key1)
						if err != nil {
							return nil, err
						}

						res, err := p.dspf2N.CombineMultipleResults(feval0, feval1)
						if len(res) != p.t*p.t {
							return nil, fmt.Errorf("step 2: length of OLE DSPF FullEval is %d but is expected to be t^2=%d", len(res), p.t*p.t)
						}

						err = wrs.SparseBigAdd(res)
						if err != nil {
							return nil, err
						}
					}
				}
			}
			w[r][s] = wrs
		}
	}

	// 3. Process second OLE seed
	m := make([][]*poly.Polynomial, p.c)
	for r := 0; r < p.c; r++ {
		m[r] = make([]*poly.Polynomial, p.c)
		for s := 0; s < p.c; s++ {
			ur := u[r].Copy()      // We need unmodified u[r] later on, so we copy it
			ks := k[s].Copy()      // We need unmodified k[s] later on, so we copy it
			mrs, err := ur.Mul(ks) // u[r] * k[s]
			if err != nil {
				return nil, err
			}
			for i := 0; i < p.n; i++ {
				for j := 0; j < p.n; j++ {
					if i != j { // Ony cross terms
						fmt.Println("OLE #2 progress: ", i, j, r, "of", p.n, p.n, p.c)
						feval0, err := p.dspf2N.FullEvalFast(seed.V[i][j][r][s].Key0)
						if err != nil {
							return nil, err
						}
						feval1, err := p.dspf2N.FullEvalFast(seed.V[i][j][r][s].Key1)
						if err != nil {
							return nil, err
						}

						res, err := p.dspf2N.CombineMultipleResults(feval0, feval1)
						if len(res) != p.t*p.t {
							return nil, fmt.Errorf("step 2: length of OLE DSPF FullEval is %d but is expected to be t^2=%d", len(res), p.t*p.t)
						}

						err = mrs.SparseBigAdd(res)
						if err != nil {
							return nil, err
						}
						// print mrs non-zero elements

					}
				}
			}
			m[r][s] = mrs
		}
	}

	// 4. Calculate BBS+ Tuples from the random polynomials in a
	// 4 a) x_i
	x := one.Copy() // start with 1
	for j := 0; j < p.c; j++ {
		ajuj, err := rand[j].Mul(u[j]) // a[j] * u[j] TODO: Implement partly sparse multiplication (a is not sparse, u[r] is)
		if err != nil {
			return nil, err
		}
		x.Add(ajuj)
	}

	return nil, nil
}

// PickRandomPolynomials picks c-1 random polynomials of degree N. The last polynomial is always 1.
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

// embedVOLECorrelations embeds VOLE correlations into DSPF keys.
func (p *PCG) embedVOLECorrelations(omega *SampledExponents, beta [][][]*bls12381.Fr, skShares []*bls12381.Fr) ([][][]*DSPFKeyPair, error) {
	U := init3DSliceDspfKey(p.n, p.n, p.c)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.n; j++ {
			if i != j {
				for r := 0; r < p.c; r++ {
					nonZeroElements := scalarMulFr(skShares[i], beta[i][r])
					key1, key2, err := p.dspfN.Gen(omega.values[i][r], frSliceToBigIntSlice(nonZeroElements))
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
func (p *PCG) embedOLECorrelations(omega, o *SampledExponents, beta, b [][][]*bls12381.Fr) ([][][][]*DSPFKeyPair, error) {
	U := init4DSliceDspfKey(p.n, p.n, p.c)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.n; j++ {
			if i != j {
				for r := 0; r < p.c; r++ {
					for s := 0; s < p.c; s++ {
						// As computing the outer sum between omega and o can result in duplicate special points, we need to check for this
						// and generate a new o if this is the case until we have a set of special points without duplicates.
						specialPoints := outerSumBigInt(omega.values[i][r], o.values[j][s]) // We can only change o, as omega is used in the other OLE correlation
						for hasDuplicates(specialPoints) {
							maxExp := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(p.N)), nil)
							maxExp.Sub(maxExp, big.NewInt(1))

							vec := make([]*big.Int, 0, p.t)
							elementSet := make(map[*big.Int]bool)
							for len(vec) < p.t {
								randNum := big.NewInt(0)
								randNum.Rand(p.rng, maxExp)

								if !elementSet[randNum] {
									elementSet[randNum] = true
									vec = append(vec, randNum)
								}
							}

							// Sort vec. This makes it easier to convert to a polynomial later on.
							sort.Slice(vec, func(i, j int) bool {
								return vec[i].Cmp(vec[j]) < 0
							})

							o.values[j][s] = vec
							specialPoints = outerSumBigInt(omega.values[i][r], o.values[j][s])
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

// sampleExponents samples values later used as poly exponents by picking p.n*p.c random t-vectors from N.
func (p *PCG) sampleExponents() *SampledExponents {
	// The maximum value of an exponent is 2^N - 1
	maxExp := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(p.N)), nil)
	maxExp.Sub(maxExp, big.NewInt(1))

	exp := init3DSliceBigInt(p.n, p.c, p.t)
	for i := 0; i < p.n; i++ {
		for j := 0; j < p.c; j++ {
			vec := make([]*big.Int, 0, p.t)
			elementSet := make(map[*big.Int]bool)

			for len(vec) < p.t {
				randNum := big.NewInt(0)
				randNum.Rand(p.rng, maxExp)

				if !elementSet[randNum] {
					elementSet[randNum] = true
					vec = append(vec, randNum)
				}
			}

			// Sort vec. This makes it easier to convert to a polynomial later on.
			sort.Slice(vec, func(i, j int) bool {
				return vec[i].Cmp(vec[j]) < 0
			})

			exp[i][j] = vec
		}
	}
	return &SampledExponents{exp}
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
