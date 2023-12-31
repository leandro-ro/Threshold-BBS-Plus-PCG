package pcg

import (
	"bytes"
	"encoding/gob"
	bls12381 "github.com/kilic/bls12-381"
)

// GeneratedTuples holds the shares of the pre-computed ECDSA signatures generated by the Eval function of the PCG.
type GeneratedTuples struct {
	Sk     *bls12381.Fr
	Tuples []*Tuple
}

// Tuple is a share of a pre-computed ECDSA signature generated by the Eval function of the PCG.
type Tuple struct {
	SkShare  *bls12381.Fr
	AShare   *bls12381.Fr
	EShare   *bls12381.Fr
	SShare   *bls12381.Fr
	AeTerms  []*OLECorrelation
	SeTerms  []*OLECorrelation
	AskTerms []*OLECorrelation
}

// EmptyTuple returns an empty Tuple.
// The amount of AeTerms, SeTerms and AskTerms is determined by s.
func EmptyTuple(s int) *Tuple {
	t := &Tuple{
		SkShare:  bls12381.NewFr(),
		AShare:   bls12381.NewFr(),
		EShare:   bls12381.NewFr(),
		SShare:   bls12381.NewFr(),
		AeTerms:  make([]*OLECorrelation, s),
		SeTerms:  make([]*OLECorrelation, s),
		AskTerms: make([]*OLECorrelation, s),
	}

	// Initialize AeTerms, SeTerms, and AskTerms
	for i := 0; i < s; i++ {
		t.AeTerms[i] = EmptyOLECorrelation()
		t.SeTerms[i] = EmptyOLECorrelation()
		t.AskTerms[i] = EmptyOLECorrelation()
	}

	return t
}

// Serialize converts a Tuple into a byte slice.
func (t *Tuple) Serialize() ([]byte, error) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)

	// serialize each field of Tuple
	if err := encoder.Encode(t.SkShare.ToBytes()); err != nil {
		return nil, err
	}

	if err := encoder.Encode(t.AShare.ToBytes()); err != nil {
		return nil, err
	}

	if err := encoder.Encode(t.EShare.ToBytes()); err != nil {
		return nil, err
	}

	if err := encoder.Encode(t.SShare.ToBytes()); err != nil {
		return nil, err
	}

	// Serialize AeTerms
	if err := encoder.Encode(len(t.AeTerms)); err != nil {
		return nil, err
	}
	for _, aeTerm := range t.AeTerms {
		aeTermBytes, err := aeTerm.Serialize()
		if err != nil {
			return nil, err
		}
		if err := encoder.Encode(aeTermBytes); err != nil {
			return nil, err
		}
	}

	// Serialize SeTerms
	if err := encoder.Encode(len(t.SeTerms)); err != nil {
		return nil, err
	}
	for _, seTerm := range t.SeTerms {
		seTermBytes, err := seTerm.Serialize()
		if err != nil {
			return nil, err
		}
		if err := encoder.Encode(seTermBytes); err != nil {
			return nil, err
		}
	}

	// Serialize AskTerms
	if err := encoder.Encode(len(t.AskTerms)); err != nil {
		return nil, err
	}
	for _, askTerm := range t.AskTerms {
		askTermBytes, err := askTerm.Serialize()
		if err != nil {
			return nil, err
		}
		if err := encoder.Encode(askTermBytes); err != nil {
			return nil, err
		}
	}

	return b.Bytes(), nil
}

// Deserialize converts a byte slice into a Tuple.
func (t *Tuple) Deserialize(data []byte) error {
	b := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(b)

	// Deserialize SkShare, AShare, EShare, SShare
	var skShareBytes, aShareBytes, eShareBytes, sShareBytes []byte
	if err := decoder.Decode(&skShareBytes); err != nil {
		return err
	}
	t.SkShare.FromBytes(skShareBytes)

	if err := decoder.Decode(&aShareBytes); err != nil {
		return err
	}
	t.AShare.FromBytes(aShareBytes)

	if err := decoder.Decode(&eShareBytes); err != nil {
		return err
	}
	t.EShare.FromBytes(eShareBytes)

	if err := decoder.Decode(&sShareBytes); err != nil {
		return err
	}
	t.SShare.FromBytes(sShareBytes)

	// Deserialize AeTerms
	var aeTermsSize int
	if err := decoder.Decode(&aeTermsSize); err != nil {
		return err
	}
	t.AeTerms = make([]*OLECorrelation, aeTermsSize)
	for i := 0; i < aeTermsSize; i++ {
		var oleBytes []byte
		if err := decoder.Decode(&oleBytes); err != nil {
			return err
		}
		t.AeTerms[i] = EmptyOLECorrelation()
		if err := t.AeTerms[i].Deserialize(oleBytes); err != nil {
			return err
		}
	}

	// Deserialize SeTerms
	var seTermsSize int
	if err := decoder.Decode(&seTermsSize); err != nil {
		return err
	}
	t.SeTerms = make([]*OLECorrelation, seTermsSize)
	for i := 0; i < seTermsSize; i++ {
		var oleBytes []byte
		if err := decoder.Decode(&oleBytes); err != nil {
			return err
		}
		t.SeTerms[i] = EmptyOLECorrelation()
		if err := t.SeTerms[i].Deserialize(oleBytes); err != nil {
			return err
		}
	}

	// Deserialize AskTerms
	var askTermsSize int
	if err := decoder.Decode(&askTermsSize); err != nil {
		return err
	}
	t.AskTerms = make([]*OLECorrelation, askTermsSize)
	for i := 0; i < askTermsSize; i++ {
		var oleBytes []byte
		if err := decoder.Decode(&oleBytes); err != nil {
			return err
		}
		t.AskTerms[i] = EmptyOLECorrelation()
		if err := t.AskTerms[i].Deserialize(oleBytes); err != nil {
			return err
		}
	}

	return nil
}

// OLECorrelation holds u and v s.t. for some x, y the following holds: x * y = U + V
type OLECorrelation struct {
	U *bls12381.Fr
	V *bls12381.Fr
}

// EmptyOLECorrelation returns an empty OLECorrelation.
func EmptyOLECorrelation() *OLECorrelation {
	return &OLECorrelation{bls12381.NewFr(), bls12381.NewFr()}
}

// Serialize converts an OLECorrelation into a byte slice.
func (o *OLECorrelation) Serialize() ([]byte, error) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)

	if err := encoder.Encode(o.U.ToBytes()); err != nil {
		return nil, err
	}
	if err := encoder.Encode(o.V.ToBytes()); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// Deserialize converts a byte slice into an OLECorrelation.
func (o *OLECorrelation) Deserialize(data []byte) error {
	b := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(b)

	var uBytes, vBytes []byte
	if err := decoder.Decode(&uBytes); err != nil {
		return err
	}
	if err := decoder.Decode(&vBytes); err != nil {
		return err
	}

	o.U.FromBytes(uBytes)
	o.V.FromBytes(vBytes)
	return nil
}