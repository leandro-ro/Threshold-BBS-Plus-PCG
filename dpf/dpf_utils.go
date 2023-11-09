package dpf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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
// TODO: According the CPU profiler, this is a performance bottleneck for Eval. Consider investigating this further.
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

// NextPrime returns the next prime number greater than n.
func NextPrime(n *big.Int) *big.Int {
	// Make a copy of n to avoid modifying the input value
	start := new(big.Int).Set(n)

	// If start is less than 2, return 2
	two := big.NewInt(2)
	if start.Cmp(two) < 0 {
		return two
	}

	// Increment start until it's odd, if it was even
	if start.Bit(0) == 0 {
		start.Add(start, big.NewInt(1))
	} else {
		// If start is odd, start checking from the next possible prime
		start.Add(start, big.NewInt(2))
	}

	// Search for the next prime
	for {
		if start.ProbablyPrime(20) {
			return start
		}
		start.Add(start, big.NewInt(2))
	}
}

// ExtendBigIntToBitLength takes a big.Int 'a' and extends its bit representation with leading zeros to 'lambda' bits.
// It returns an error if a's bit length is greater than 'lambda'.
func ExtendBigIntToBitLength(a *big.Int, lambda int) ([]uint, error) {
	if a.BitLen() > lambda {
		return nil, errors.New("bit length of 'a' exceeds 'lambda'")
	}

	bitRepresentation := make([]uint, lambda)
	for i := 0; i < lambda; i++ {
		bitRepresentation[lambda-i-1] = uint(a.Bit(i))
	}
	return bitRepresentation, nil
}

// IncrementBytes takes a number 'b' represented as []byte, increments it by 'val', and returns the incremented value as []byte.
// The returned []byte will always have the same length as the input 'b'. If the incremented value results in a shorter []byte slice,
// it is padded with zeros on the left. If it overflows the length of the original slice, the most significant bytes are truncated.
func IncrementBytes(b []byte, val int) []byte {
	// Convert the []byte slice to a *big.Int
	num := new(big.Int).SetBytes(b)

	// Increment the *big.Int value
	num.Add(num, big.NewInt(int64(val)))

	// Convert back to []byte slice
	result := num.Bytes()

	// Check if the resulting slice is shorter than the original
	for len(result) < len(b) {
		result = append([]byte{0}, result...)
	}

	// Check if the resulting slice is longer than the original
	if len(result) > len(b) {
		overflow := len(result) - len(b)
		result = result[overflow:]
	}

	return result
}
