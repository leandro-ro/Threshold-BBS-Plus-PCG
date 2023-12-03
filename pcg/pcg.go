package pcg

import (
	"math/rand"
	"pcg-master-thesis/dpf"
)

type PCG struct {
	lambda int     // lambda is the security parameter used to determine the output length of the underlying PRandomG
	N      int     // N is the domain of the PCG
	n      int     // n is the number of parties participating in this PCG
	c      int     // c is the first security parameter of the Module-LPN assumption
	t      int     // t is the second security parameter of the Module-LPN assumption
	dpf    dpf.DPF // dpf is the underlying Point Function used to construct the PCG
}

func NewPCG(lambda, N, n, c, t int, dpf dpf.DPF) *PCG {
	return &PCG{
		lambda: lambda,
		N:      N,
		n:      n,
		c:      c,
		t:      t,
		dpf:    dpf,
	}
}

// CentralizedGen generates a seed for each party as a central dealer.
// The goal is to realize a distributed generation of the seed.
func (p *PCG) CentralizedGen() ([]*Seed, error) {
	// Notation of the variables analogue to the notation from the formal definition of PCG
	// 1. Generate key shares for each party
	seed, err := bytesToInt64(dpf.RandomSeed(8))
	if err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewSource(seed))
	_, skShares := GetShamirSharedRandomElement(rng, p.n, p.n) // TODO: determine how we set the threshold for the signature scheme

	// 2a. Initialize omega, eta, and phi by sampling at random from N
	omega := 0
	eta := 0
	phi := 0

	// 2b. Initialize beta, gamma and epsilon by sampling at random from F_q (bls12381.Fr)
	beta := 0
	gamma := 0
	epsilon := 0

	return nil, nil
}

// pickTFromN picks p.t random elements from N and returns them
func (p *PCG) pickTFromN() {

}

func (p *PCG) pickTFromFq() {

}
