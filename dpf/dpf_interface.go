package dpf

import (
	"math/big"
)

// KeyType identifies the type of DPF Key.
type KeyType string

// TreeDPFKeyID defines each key type identifier as a constant.
// Used to differentiate between different key types in the generic dspf implementation.
const (
	OpTreeDPFKeyID KeyType = "OpTreeDPFKey"
	// ... other key type identifiers
)

// KeyIDs is a slice of all key type identifiers.
var KeyIDs = []KeyType{
	OpTreeDPFKeyID,
	// ... other key type identifiers
}

// Key is an interface for DPF keys.
type Key interface {
	Serialize() ([]byte, error)
	Deserialize(data []byte) error
	TypeID() KeyType
}

// DPF is an interface for Distributed Point Functions.
type DPF interface {
	Gen(specialPointX *big.Int, nonZeroElementY *big.Int) (Key, Key, error)
	Eval(key Key, x *big.Int) (*big.Int, error)
	FullEval(key Key) ([]*big.Int, error)
	FullEvalFast(key Key) ([]*big.Int, error)
	CombineResults(y1 *big.Int, y2 *big.Int) *big.Int
	ChangeDomain(domain int)
	GetDomain() int
}
