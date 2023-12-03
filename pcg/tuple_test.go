package pcg_test

import (
	bls12381 "github.com/kilic/bls12-381"
	"pcg-master-thesis/pcg"
	"reflect"
	"testing"
)

func TestTupleSerialization(t *testing.T) {
	original := pcg.EmptyTuple(2)

	original.SkShare = bls12381.NewFr().One()
	original.AShare = bls12381.NewFr().Zero()
	original.EShare = bls12381.NewFr().Zero()
	original.SShare = bls12381.NewFr().Zero()
	original.AeTerms[0] = pcg.EmptyOLECorrelation()
	original.AeTerms[0].U = bls12381.NewFr().One()
	original.AeTerms[0].V = bls12381.NewFr().Zero()
	original.AeTerms[1] = pcg.EmptyOLECorrelation()
	original.AeTerms[1].U = bls12381.NewFr().Zero()
	original.AeTerms[1].V = bls12381.NewFr().One()
	original.SeTerms[0] = pcg.EmptyOLECorrelation()
	original.SeTerms[0].U = bls12381.NewFr().One()
	original.SeTerms[0].V = bls12381.NewFr().Zero()
	original.SeTerms[1] = pcg.EmptyOLECorrelation()
	original.SeTerms[1].U = bls12381.NewFr().Zero()
	original.SeTerms[1].V = bls12381.NewFr().One()
	original.AskTerms[0] = pcg.EmptyOLECorrelation()
	original.AskTerms[0].U = bls12381.NewFr().One()
	original.AskTerms[0].V = bls12381.NewFr().Zero()
	original.AskTerms[1] = pcg.EmptyOLECorrelation()
	original.AskTerms[1].U = bls12381.NewFr().Zero()
	original.AskTerms[1].V = bls12381.NewFr().One()

	// Serialize the object
	serializedData, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Deserialize the object
	deserialized := pcg.EmptyTuple(2)
	err = deserialized.Deserialize(serializedData)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	// Compare original and deserialized objects
	if !reflect.DeepEqual(original, deserialized) {
		t.Errorf("Deserialized object does not match original, got: %+v, want: %+v", deserialized, original)
	}
}

func TestOLECorrelationSerialization(t *testing.T) {
	// Initialize a test OLECorrelation object
	original := pcg.EmptyOLECorrelation()
	original.U = bls12381.NewFr().One()
	original.V = bls12381.NewFr().Zero()

	// Serialize the object
	serializedData, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Deserialize the object
	deserialized := pcg.EmptyOLECorrelation()
	err = deserialized.Deserialize(serializedData)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	// Compare original and deserialized objects
	if !reflect.DeepEqual(original, deserialized) {
		t.Errorf("Deserialized object does not match original, got: %+v, want: %+v", deserialized, original)
	}
}
