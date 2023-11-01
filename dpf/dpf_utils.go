package dpf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math/big"
)

// RandomBit generates a cryptographically secure random bit returned as a bool.
func RandomBit() bool {
	randomByte := make([]byte, 1)
	_, err := rand.Read(randomByte)
	if err != nil {
		panic(err.Error())
	}
	return (randomByte[0] & 1) == 1
}

// RandomSeed generates a cryptographically secure random seed with the given length in bytes.
func RandomSeed(length int) []byte {
	seed := make([]byte, length)
	_, err := rand.Read(seed)
	if err != nil {
		panic(err.Error())
	}
	return seed
}

// PRG generates pseudorandom bytes of given length using AES-CTR.
func PRG(seed []byte, length int) []byte {
	// Create a new AES cipher block with the given seed
	block, err := aes.NewCipher(seed)
	if err != nil {
		panic(err)
	}

	// Create a slice to hold the output
	output := make([]byte, length)

	// Use a constant IV (Initialization Vector)
	iv := make([]byte, aes.BlockSize) // all zeros

	// Create a new AES-CTR stream cipher
	stream := cipher.NewCTR(block, iv)

	// Generate the pseudorandom bytes
	stream.XORKeyStream(output, output)

	return output
}

func XORBytes(arrays ...[]byte) []byte {
	// Assume all byte slices have the same length for simplicity.
	n := len(arrays[0])
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		for _, arr := range arrays {
			result[i] ^= arr[i]
		}
	}
	return result
}

// NextOddPrime returns the next odd prime number greater than or equal to n.
func NextOddPrime(n int) int {
	// Start from n; if n is even, go to the next odd number
	start := big.NewInt(int64(n))
	if start.Bit(0) == 0 {
		start.Add(start, big.NewInt(1))
	}

	// Search for the next odd prime
	for {
		if start.ProbablyPrime(20) {
			return int(start.Int64())
		}
		start.Add(start, big.NewInt(2))
	}
}

// CheckCoprime returns 0 if a and b are coprime, otherwise it returns the delta to add to b to make them coprime.
func CheckCoprime(a, b *big.Int) *big.Int {
	delta := big.NewInt(0)
	one := big.NewInt(1)
	gcd := big.NewInt(0)
	temp := new(big.Int)

	for {
		gcd.GCD(nil, nil, a, temp.Add(b, delta))
		if gcd.Cmp(one) == 0 {
			return delta
		}
		delta.Add(delta, one)
	}
}

// DistributeSum randomly distribute 'sum' into two parts.
func DistributeSum(sum *big.Int) [2]*big.Int {
	var sumCompensation [2]*big.Int

	if sum.Cmp(big.NewInt(0)) == 0 {
		return [2]*big.Int{big.NewInt(0), big.NewInt(0)}
	}

	// Generate a random big.Int between 0 and sum
	randPart, _ := rand.Int(rand.Reader, sum)

	// Calculate the other part so that randPart + otherPart = sum
	otherPart := new(big.Int).Sub(sum, randPart)

	sumCompensation[0] = randPart
	sumCompensation[1] = otherPart

	return sumCompensation
}
