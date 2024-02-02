package dpf

import (
	"testing"
)

// TestRandomSeed tests the RandomSeed function.
func TestRandomSeedLength(t *testing.T) {
	length := 16
	seed := RandomSeed(length)
	if len(seed) != length {
		t.Errorf("RandomSeed() generated a seed of incorrect length: got %v, want %v", len(seed), length)
	}
}

// TestRandomSeed tests the RandomSeed function.
func TestRandomSeedDuplicates(t *testing.T) {
	length := 16
	seed0 := RandomSeed(length)
	seed1 := RandomSeed(length)
	if string(seed0) == string(seed1) {
		t.Errorf("RandomSeed() generated the same seed after multiple callse. This is extremly unlikely.")
	}
}

// TestPRGWithSameSeed tests that PRG is deterministic for the same seed.
func TestPRGWithSameSeed(t *testing.T) {
	seed := RandomSeed(16)
	length := 32

	output1 := PRG(seed, length)
	output2 := PRG(seed, length)

	if string(output1) != string(output2) {
		t.Errorf("PRG() with the same seed should produce the same output: got %v and %v", output1, output2)
	}
}

// TestPRGWithDifferentSeeds tests that PRG produces different outputs for different seeds.
func TestPRGWithDifferentSeeds(t *testing.T) {
	seed1 := RandomSeed(16)
	seed2 := RandomSeed(16)

	// Make sure seed1 and seed2 are different for the test.
	for string(seed1) == string(seed2) {
		seed2 = RandomSeed(16)
	}

	length := 32

	output1 := PRG(seed1, length)
	output2 := PRG(seed2, length)

	if string(output1) == string(output2) {
		t.Errorf("PRG() with different seeds should produce different outputs: got %v and %v", output1, output2)
	}
}

func BenchmarkAES128(b *testing.B) {
	seed := RandomSeed(16)
	outputLength := 16 // 16 bytes = 128 bits
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		PRG(seed, outputLength)
	}
}

func BenchmarkAES192(b *testing.B) {
	seed := RandomSeed(16)
	outputLength := 24 // 24 bytes = 192 bits
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		PRG(seed, outputLength)
	}
}

func BenchmarkAES256(b *testing.B) {
	seed := RandomSeed(16)
	outputLength := 32 // 32 bytes = 256 bits
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		PRG(seed, outputLength)
	}
}
