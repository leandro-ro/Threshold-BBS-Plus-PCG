package dpf

import "math/big"

// Key is an interface for DPF keys.
type Key interface {
	Serialize() ([]byte, error)
	Deserialize(data []byte) error
}

// DPF is an interface for Distributed Point Functions.
type DPF interface {
	Gen(specialPointX *big.Int, nonZeroElementY *big.Int) (Key, Key, error)
	Eval(key Key, x *big.Int) (*big.Int, error)
}
