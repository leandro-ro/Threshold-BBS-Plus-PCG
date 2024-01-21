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

func ConvertBitArrayToBytes(bits []uint) []byte {
	bytes := make([]byte, (len(bits)+7)/8)
	for i, bit := range bits {
		if bit == 1 {
			bytes[(len(bits)-1-i)/8] |= 1 << (uint(i) % 8)
		}
	}
	return bytes
}

// InitializeMap3LevelsBytes initializes a 3-level nested map with byte slices.
func InitializeMap3LevelsBytes(keys1, keys2, keys3 []int) map[int]map[int]map[int][]byte {
	m := make(map[int]map[int]map[int][]byte)
	for _, k1 := range keys1 {
		m[k1] = make(map[int]map[int][]byte)
		for _, k2 := range keys2 {
			m[k1][k2] = make(map[int][]byte)
			for _, k3 := range keys3 {
				m[k1][k2][k3] = nil
			}
		}
	}
	return m
}

// InitializeMap2LevelsBytes initializes a 2-level nested map with byte slices.
func InitializeMap2LevelsBytes(keys1, keys2 []int) map[int]map[int][]byte {
	m := make(map[int]map[int][]byte)
	for _, k1 := range keys1 {
		m[k1] = make(map[int][]byte)
		for _, k2 := range keys2 {
			m[k1][k2] = nil
		}
	}
	return m
}

// InitializeMap3LevelsBool initializes a 3-level nested map with boolean values.
func InitializeMap3LevelsBool(keys1, keys2, keys3 []int) map[int]map[int]map[int]bool {
	m := make(map[int]map[int]map[int]bool)
	for _, k1 := range keys1 {
		m[k1] = make(map[int]map[int]bool)
		for _, k2 := range keys2 {
			m[k1][k2] = make(map[int]bool)
			for _, k3 := range keys3 {
				m[k1][k2][k3] = false
			}
		}
	}
	return m
}

// InitializeMap2LevelsBool initializes a 2-level nested map with boolean values.
func InitializeMap2LevelsBool(keys1, keys2 []int) map[int]map[int]bool {
	m := make(map[int]map[int]bool)
	for _, k1 := range keys1 {
		m[k1] = make(map[int]bool)
		for _, k2 := range keys2 {
			m[k1][k2] = false
		}
	}
	return m
}

// MakeRange creates a slice of integers ranging from min to max.
func MakeRange(min, max int) []int {
	a := make([]int, max-min)
	for i := range a {
		a[i] = min + i
	}
	return a
}
