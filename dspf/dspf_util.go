package dspf

import (
	"errors"
	"pcg-bbs-plus/dpf"
	"pcg-bbs-plus/dpf/optreedpf"
)

// CreateKeyFromTypeID is a helper function that instantiates a DPF key based on the typeID.
func CreateKeyFromTypeID(typeID dpf.KeyType) (dpf.Key, error) {
	switch typeID {
	case dpf.OpTreeDPFKeyID:
		return optreedpf.EmptyKey(), nil
	// Add cases for other key types here
	default:
		return nil, errors.New("unknown key type")
	}
}
