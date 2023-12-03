package pcg

import (
	"encoding/binary"
	"fmt"
	bls12381 "github.com/kilic/bls12-381"
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
