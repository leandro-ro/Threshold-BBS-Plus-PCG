package dspf

import (
	"fmt"
	"math/big"
	treedpf "pcg-master-thesis/dpf/2015_boyle_tree_based"
	optreedpf "pcg-master-thesis/dpf/2018_boyle_optimization"
	"testing"
)

func TestGenMismatchedLengths(t *testing.T) {
	var dspfInstance DSPF
	specialPoints := []*big.Int{big.NewInt(1)}
	nonZeroElements := []*big.Int{big.NewInt(2), big.NewInt(3)}

	_, _, err := dspfInstance.Gen(specialPoints, nonZeroElements)
	if err == nil || err.Error() != "the number of special points and non-zero elements must match" {
		t.Errorf("Gen did not return the correct error for mismatched lengths")
	}
}

func TestGenNilValues(t *testing.T) {
	var dspfInstance DSPF
	specialPoints := []*big.Int{nil}
	nonZeroElements := []*big.Int{big.NewInt(2)}

	_, _, err := dspfInstance.Gen(specialPoints, nonZeroElements)
	if err == nil || err.Error() != "special points and non-zero elements cannot be nil" {
		t.Errorf("Gen did not return the correct error for nil values")
	}
}

func TestGenDuplicateSpecialPoints(t *testing.T) {
	var dspfInstance DSPF
	specialPoint := big.NewInt(1)
	specialPoints := []*big.Int{specialPoint, specialPoint}
	nonZeroElements := []*big.Int{big.NewInt(2), big.NewInt(3)}

	_, _, err := dspfInstance.Gen(specialPoints, nonZeroElements)
	if err == nil || err.Error() != fmt.Sprintf("duplicate special point: %s", specialPoint.Text(10)) {
		t.Errorf("Gen did not return the correct error for duplicate special points")
	}
}

func TestDSPFWithTreeDPF(t *testing.T) {
	treeDPF128, err := treedpf.InitFactory(128)
	if err != nil {
		t.Errorf("InitFactory returned an unexpected error: %v", err)
	}
	dspf := NewDSPFFactory(treeDPF128)
	sp1 := big.NewInt(1)
	nz1 := big.NewInt(3)

	sp2 := big.NewInt(5)
	nz2 := big.NewInt(61)

	sp3 := big.NewInt(27)
	nz3 := big.NewInt(82)

	specialPoints := []*big.Int{sp1, sp2, sp3}
	nonZeroElements := []*big.Int{nz1, nz2, nz3}

	var keyAlice Key
	var keyBob Key
	keyAlice, keyBob, err = dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		t.Errorf("Gen returned an unexpected error for valid input: %v", err)
	}
	if keyAlice.DPFKeys == nil || keyBob.DPFKeys == nil {
		t.Errorf("Gen returned nil keys")
	}

	// Test Eval
	x := big.NewInt(2)
	var ysAlice []*big.Int
	var ysBob []*big.Int
	ysAlice, err = dspf.Eval(keyAlice, x)
	if err != nil {
		t.Errorf("Eval returned an unexpected error: %v", err)
	}
	ysBob, err = dspf.Eval(keyBob, x)
	if err != nil {
		t.Errorf("Eval returned an unexpected error: %v", err)
	}

	// Test CombineResults
	var result *big.Int
	result, err = dspf.CombineResults(ysAlice, ysBob)
	if err != nil {
		t.Errorf("CombineResults returned an unexpected error: %v", err)
	}
	// Expect result to be zero
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("CombineResults did not return zero")
	}

	// Test Eval with non-zero result
	x = sp2
	ysAlice, err = dspf.Eval(keyAlice, x)
	if err != nil {
		t.Errorf("Eval returned an unexpected error: %v", err)
	}
	ysBob, err = dspf.Eval(keyBob, x)
	if err != nil {
		t.Errorf("Eval returned an unexpected error: %v", err)
	}
	result, err = dspf.CombineResults(ysAlice, ysBob)
	if err != nil {
		t.Errorf("CombineResults returned an unexpected error: %v", err)
	}

	// Expect result to be non-zero
	if result.Cmp(nz2) != 0 {
		t.Errorf("CombineResults did not return the correct result")
	}
}

func TestDSPFWithOpTreeDPF(t *testing.T) {
	treeDPF128, err := optreedpf.InitFactory(128)
	if err != nil {
		t.Errorf("InitFactory returned an unexpected error: %v", err)
	}
	dspf := NewDSPFFactory(treeDPF128)
	sp1 := big.NewInt(1)
	nz1 := big.NewInt(3)

	sp2 := big.NewInt(5)
	nz2 := big.NewInt(61)

	sp3 := big.NewInt(27)
	nz3 := big.NewInt(82)

	specialPoints := []*big.Int{sp1, sp2, sp3}
	nonZeroElements := []*big.Int{nz1, nz2, nz3}

	var keyAlice Key
	var keyBob Key
	keyAlice, keyBob, err = dspf.Gen(specialPoints, nonZeroElements)
	if err != nil {
		t.Errorf("Gen returned an unexpected error for valid input: %v", err)
	}
	if keyAlice.DPFKeys == nil || keyBob.DPFKeys == nil {
		t.Errorf("Gen returned nil keys")
	}

	// Test Eval
	x := big.NewInt(2)
	var ysAlice []*big.Int
	var ysBob []*big.Int
	ysAlice, err = dspf.Eval(keyAlice, x)
	if err != nil {
		t.Errorf("Eval returned an unexpected error: %v", err)
	}
	ysBob, err = dspf.Eval(keyBob, x)
	if err != nil {
		t.Errorf("Eval returned an unexpected error: %v", err)
	}

	// Test CombineResults
	var result *big.Int
	result, err = dspf.CombineResults(ysAlice, ysBob)
	if err != nil {
		t.Errorf("CombineResults returned an unexpected error: %v", err)
	}
	// Expect result to be zero
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("CombineResults did not return zero")
	}

	// Test Eval with non-zero result
	x = sp2
	ysAlice, err = dspf.Eval(keyAlice, x)
	if err != nil {
		t.Errorf("Eval returned an unexpected error: %v", err)
	}
	ysBob, err = dspf.Eval(keyBob, x)
	if err != nil {
		t.Errorf("Eval returned an unexpected error: %v", err)
	}
	result, err = dspf.CombineResults(ysAlice, ysBob)
	if err != nil {
		t.Errorf("CombineResults returned an unexpected error: %v", err)
	}

	// Expect result to be non-zero
	if result.Cmp(nz2) != 0 {
		t.Errorf("CombineResults did not return the correct result")
	}
}
