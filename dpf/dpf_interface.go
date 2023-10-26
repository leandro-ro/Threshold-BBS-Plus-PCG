package dpf

import "math/big"

// Key is an interface for DPF keys.
type Key interface {
	// Methods that every DPF key must implement
	// For example, we might have methods for serializing or deserializing the key here
}

// DPF is an interface for Distributed Point Functions.
type DPF interface {
	Gen(specialPointX *big.Int, nonZeroElementY *big.Int) (Key, Key, error)
	Eval(key Key, x *big.Int) (*big.Int, error)
}
