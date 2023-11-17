package dspf

import (
	"errors"
	"pcg-master-thesis/dpf"
	treedpf "pcg-master-thesis/dpf/2015_boyle_tree_based"
	optreedpf "pcg-master-thesis/dpf/2018_boyle_optimization"
)

// CreateKeyFromTypeID is a helper function that instantiates a DPF key based on the typeID.
func CreateKeyFromTypeID(typeID dpf.KeyType) (dpf.Key, error) {
	switch typeID {
	case dpf.TreeDPFKeyID:
		return treedpf.EmptyKey(), nil
	case dpf.OpTreeDPFKeyID:
		return optreedpf.EmptyKey(), nil
	// Add cases for other key types here
	default:
		return nil, errors.New("unknown key type")
	}
}
