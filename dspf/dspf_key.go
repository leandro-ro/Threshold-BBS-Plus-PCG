package dspf

import (
	"bytes"
	"encoding/gob"
	"io"
	"pcg-bbs-plus/dpf"
)

// Key holds the DPF keys the DSPF is constructed on.
type Key struct {
	DPFKeys []dpf.Key
}

// SerializeKeys serializes the Key into a byte slice.
func (k *Key) SerializeKeys() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	for _, key := range k.DPFKeys {
		typeID := key.TypeID()
		err := encoder.Encode(typeID) // First, encode the type identifier
		if err != nil {
			return nil, err
		}

		data, err := key.Serialize()
		if err != nil {
			return nil, err
		}
		err = encoder.Encode(data)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// DeserializeKeys deserializes the byte slice into DPFKeys.
func (k *Key) DeserializeKeys(data []byte) error {
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)

	k.DPFKeys = nil // Clear existing keys

	for {
		var typeID dpf.KeyType
		err := decoder.Decode(&typeID) // First, decode the type identifier
		if err != nil {
			if err == io.EOF {
				break // We've reached the end of the data stream
			}
			return err
		}

		var keyData []byte
		err = decoder.Decode(&keyData)
		if err != nil {
			return err
		}

		key, err := CreateKeyFromTypeID(typeID) // Instantiate the key based on the typeID
		if err != nil {
			return err
		}

		err = key.Deserialize(keyData)
		if err != nil {
			return err
		}

		k.DPFKeys = append(k.DPFKeys, key)
	}

	return nil
}

// AmountOfDPFKeys returns the amount of DPF keys the DSPF key is constructed with.
// This number corresponds to the amount of special positions/non-zero elements.
func (k *Key) AmountOfDPFKeys() int {
	return len(k.DPFKeys)
}
