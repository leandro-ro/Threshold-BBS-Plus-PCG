package pcg

import (
	"encoding/binary"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
	"math/rand"
)

// GetShamirSharedRandomElement generates a t-out-of-n shamir secret sharing of a random element.
// This function is taken from the threshold-bbs-plus-signatures repository.
func GetShamirSharedRandomElement(rng *rand.Rand, t, n int) (*bls12381.Fr, []*bls12381.Fr) {
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
			result[baseIndex+j].Add(ai, bj)
		}
	}

	return result
}

// outerProductFr calculates the outer product of two slices of *bls12381.Fr elements.
// the resulting matrix is returned in vector form.
func outerProductFr(a, b []*bls12381.Fr) []*bls12381.Fr {
	result := make([]*bls12381.Fr, len(a)*len(b))

	for i, ai := range a {
		baseIndex := i * len(b)
		for j, bj := range b {
			result[baseIndex+j].Mul(ai, bj)
		}
	}

	return result
}

// scalarMulFr multiplies a scalar with a vector of *bls12381.Fr elements.
func scalarMulFr(scalar *bls12381.Fr, vector []*bls12381.Fr) []*bls12381.Fr {
	for i := 0; i < len(vector); i++ {
		vector[i].Mul(vector[i], scalar)
	}
	return vector
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

// bigIntSliceToFrSlice converts a slice of *big.Int to a slice of *bls12381.Fr
func bigIntSliceToFrSlice(s []*big.Int) []*bls12381.Fr {
	result := make([]*bls12381.Fr, len(s))
	for i, e := range s {
		result[i] = bls12381.NewFr().FromBytes(e.Bytes())
	}
	return result
}
