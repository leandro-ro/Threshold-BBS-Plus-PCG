// Package ffarithmetics provides GF(2^m) arithmetics.
//
// The library provides functionality to add, multiply,
// and find the multiplicative inverse in the field GF(2^m).
package ffarithmetics

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Define the directory and filename for caching the polynomials
const dirPath = ""
const fileName = "cached_polynomials.csv"

var fullPathToPolys = filepath.Join(dirPath, fileName)

// GF2M represents a field GF(2^m).
type GF2M struct {
	Modulus *big.Int // Modulus is the irreducible polynomial for the field GF(2^m).
}

// NewGF2M constructs a new GF2M struct which can then be used for calculations inside GF(2^m).
// It uses a given m to find or generate an irreducible polynomial for GF(2^m).
// The polynomial is then stored as a big.Int in the Modulus field.
// If NewGF2M is called for an unseen m, the generation of an irreducible polynomial might take a moment.
// For m's that NewGF2M has already seen, their respective irreducible polynomials are cached inside polynomials.csv.
// You can also use polynomials.csv to pre-define polynomials.
func NewGF2M(m int) (*GF2M, error) {
	// Check that m is an odd prime number
	if m < 2 || !big.NewInt(int64(m)).ProbablyPrime(0) || m%2 == 0 {
		return nil, fmt.Errorf("m must be an odd prime number")
	}

	// Check if polynomial for m exists in CSV
	poly, err := readPolyFromCSV(m)
	if err != nil {
		return nil, fmt.Errorf("failed to read polynomials from file: %v", err)
	}
	if poly == "" {
		// Call SageMath to get polynomial
		poly, err = GetIrreduciblePolynomial(m)
		if err != nil {
			return nil, fmt.Errorf("failed to get irreducible polynomial: %v", err)
		}
		writePolyToCSV(m, poly)
	}

	// Convert polynomial to big.Int
	modulus := polyStringToBigInt(poly)

	return &GF2M{
		Modulus: modulus,
	}, nil
}

// Add performs addition in GF(2^m).
// It takes two big.Int values a and b, and returns their sum modulo g.Modulus.
func (g *GF2M) Add(a, b *big.Int) *big.Int {
	result := new(big.Int).Add(a, b)
	result.Mod(result, g.Modulus)
	return result
}

// Mul performs multiplication in GF(2^m).
// It takes two big.Int values a and b, and returns their product modulo g.Modulus.
func (g *GF2M) Mul(a, b *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	result.Mod(result, g.Modulus)
	return result
}

// Inv finds the multiplicative inverse of a in GF(2^m).
// It returns nil if a is not coprime to g.Modulus.
func (g *GF2M) Inv(a *big.Int) *big.Int {
	result := new(big.Int).ModInverse(a, g.Modulus)
	return result
}

// GetIrreduciblePolynomial fetches the irreducible polynomial for a given m using SageMath.
// Returns an error if the polynomial could not be generated.
func GetIrreduciblePolynomial(m int) (string, error) {
	cmd := exec.Command("sage", "-c", fmt.Sprintf("print(GF(2^%d, 'x').modulus())", m))
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	result := strings.TrimSpace(out.String())
	return result, nil
}

// readPolyFromCSV reads the irreducible polynomial for a given m from a CSV file.
// If the file or the polynomial for the given m doesn't exist, returns an error.
func readPolyFromCSV(m int) (string, error) {
	file, err := os.Open(fullPathToPolys)
	if err != nil {
		if os.IsNotExist(err) {
			// Create an empty file if it does not exist
			file, err = os.Create(fullPathToPolys)
			if err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}
	defer file.Close()

	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if record[0] == fmt.Sprintf("%d", m) {
			return record[1], nil
		}
	}
	return "", nil
}

// writePolyToCSV writes the irreducible polynomial for a given m to a CSV file.
func writePolyToCSV(m int, polyStr string) {
	file, err := os.OpenFile(fullPathToPolys, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Write([]string{fmt.Sprintf("%d", m), polyStr})
	writer.Flush()
}

// polyStringToBigInt converts a polynomial string representation to its corresponding big.Int value.
// Assumes the polynomial string is in the form e.g. "x^129 + x^5 + 1".
func polyStringToBigInt(polyStr string) *big.Int {
	// Regular expression to match terms like x^129
	re := regexp.MustCompile(`x\^(\d+)`)
	matches := re.FindAllStringSubmatch(polyStr, -1)

	result := big.NewInt(0)
	temp := big.NewInt(0)

	for _, match := range matches {
		// Parse the exponent part
		exponent, err := strconv.Atoi(match[1])
		if err != nil {
			continue // skip malformed terms
		}

		// Calculate 2^exponent
		temp.Exp(big.NewInt(2), big.NewInt(int64(exponent)), nil)

		// Add it to the result
		result.Or(result, temp)
	}

	// Check for the constant term "+ 1" and add it to the result if it exists
	if regexp.MustCompile(`\+ 1`).MatchString(polyStr) {
		result.Or(result, big.NewInt(1))
	}

	return result
}
