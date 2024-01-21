package frkey

import (
	"encoding/binary"
	"math/rand"

	bls12381 "github.com/kilic/bls12-381"
)

func uint64ToFr(val uint64) *bls12381.Fr {
	fr := bls12381.NewFr()
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, val)
	fr.FromBytes(buf)
	return fr
}

// GetLagrangeCoefficientFr computes the lagrange coefficient that is to be applied to the evaluation of the polynomial
// at position evaluation_x for an interpolation to position interpolation_x if the available evaluated positions are
// defined by indices
func GetLagrangeCoefficientFr(indices []int, evaluationX int, interpolationX int) *bls12381.Fr {
	top := bls12381.NewFr().One()
	bot := bls12381.NewFr().One()

	for _, index := range indices {
		if index != evaluationX {
			tmpTop := uint64ToFr(uint64(interpolationX))
			tmpTop.Sub(tmpTop, uint64ToFr(uint64(index)))
			top.Mul(top, tmpTop)

			tmpBot := uint64ToFr(uint64(evaluationX))
			tmpBot.Sub(tmpBot, uint64ToFr(uint64(index)))
			bot.Mul(bot, tmpBot)
		}
	}
	botInv := bls12381.NewFr()
	botInv.Inverse(bot)
	top.Mul(top, botInv)

	return top
}

// Get0LagrangeCoefficientFr computes the lagrange coefficient that is to be applied to the evaluation of the polynomial
// at position evaluation_x for an interpolation to position 0 if the available evaluated positions are defined by indices
func Get0LagrangeCoefficientFr(indices []int, evaluationX int) *bls12381.Fr {
	return GetLagrangeCoefficientFr(indices, evaluationX, 0)
}

// Get0LagrangeCoefficientSetFr computes all lagrange coefficients for an interpolation to position 0 if the available
// evaluated positions are defined by indices
func Get0LagrangeCoefficientSetFr(indices []int) []*bls12381.Fr {
	coefficients := make([]*bls12381.Fr, len(indices))
	for i, idx := range indices {
		coefficients[i] = Get0LagrangeCoefficientFr(indices, idx)
	}
	return coefficients
}

// GetShamirSharedRandomElement generates a t-out-of-n shamir secret sharing of a random element
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
