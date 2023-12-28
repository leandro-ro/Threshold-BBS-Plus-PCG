package pcg

import (
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"pcg-master-thesis/dspf"
)

type SeedExponents struct {
	omega [][]*big.Int
	eta   [][]*big.Int
	phi   [][]*big.Int
}

type SeedCoefficients struct {
	beta    [][]*bls12381.Fr
	gamma   [][]*bls12381.Fr
	epsilon [][]*bls12381.Fr
}

type DSPFKeyPair struct {
	Key0 dspf.Key
	Key1 dspf.Key
}

// Seed is the seed generated by the Gen function of the PCG.
// It allows to derive ECDSA tuples from the Eval function of the PCG.
type Seed struct {
	index        int
	ski          *bls12381.Fr
	exponents    SeedExponents
	coefficients SeedCoefficients
	U            [][][]*DSPFKeyPair   // U[i][j][r]
	C            [][][][]*DSPFKeyPair // C[i][j][r][s]
	V            [][][][]*DSPFKeyPair // V[i][j][r][s]
}

func (s *Seed) Serialize() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *Seed) Deserialize(data []byte) error {
	return fmt.Errorf("not implemented")
}
