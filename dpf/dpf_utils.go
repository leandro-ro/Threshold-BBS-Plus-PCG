package dpf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
