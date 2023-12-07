package poly

import (
	"math/big"
	"sync"
)

var (
	ONE = big.NewInt(1)
	TWO = big.NewInt(2)
)

// FFT is a struct that holds the modulus and root of unity to perform a FFT with these parameters.
// Most of the code is taken from
// https://github.com/OlegJakushkin/deepblockchains/blob/81407c2359d6680d25b507b9f4b98b42eb164978/stark/primefield.go#L580
type FFT struct {
	modulus     *big.Int
	rootOfUnity *big.Int
}

func NewFFT(modulus *big.Int, rootOfUnity *big.Int) *FFT {
	if modulus == nil || rootOfUnity == nil {
		panic("modulus or rootOfUnity cannot be nil")
	}

	// Example check: verify if rootOfUnity^order equals 1 mod modulus
	// You'll need to define 'order' based on your FFT requirements
	order := new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil) // This is just an example value
	check := new(big.Int).Exp(rootOfUnity, order, modulus)
	if check.Cmp(ONE) != 0 {
		panic("rootOfUnity is not a valid root of unity for the given order and modulus")
	}

	return &FFT{modulus, rootOfUnity}
}

func (f *FFT) MulPolysFFT(a []*big.Int, b []*big.Int) []*big.Int {
	x1 := f.fft(a, false)
	x2 := f.fft(b, false)
	c := make([]*big.Int, len(x1))
	t := new(big.Int)
	for i, v1 := range x1 {
		t.Mul(v1, x2[i])
		c[i] = new(big.Int).Mod(t, f.modulus)
	}
	return f.fft(c, true)
}

func (f *FFT) fft(vals []*big.Int, inv bool) []*big.Int {
	// Build up roots of unity
	rootz := make([]*big.Int, 2)
	rootz[0] = new(big.Int).Set(ONE)
	rootz[1] = f.rootOfUnity

	i := 1
	for rootz[i].Cmp(ONE) != 0 {
		t := new(big.Int).Mul(rootz[i], f.rootOfUnity)
		rootz = append(rootz, t.Mod(t, f.modulus))
		i = i + 1
	}

	// Fill in vals with zeroes if needed
	if len(rootz) > len(vals)+1 {
		extrazeros := make([]*big.Int, len(rootz)-len(vals)-1)
		for i := 0; i < len(extrazeros); i++ {
			extrazeros[i] = new(big.Int)
		}
		vals = append(vals, extrazeros...)
	}

	if inv {
		// Inverse FFT
		t := new(big.Int).Sub(f.modulus, TWO)
		invlen := new(big.Int).Exp(big.NewInt(int64(len(vals))), t, f.modulus)
		irootz := make([]*big.Int, 0)
		for i := len(rootz) - 1; i > 0; i-- {
			irootz = append(irootz, rootz[i])
		}

		res := f._fft(vals, irootz)

		o := make([]*big.Int, len(res))
		q := new(big.Int)
		for i, x := range res {
			q.Mul(x, invlen)
			o[i] = new(big.Int).Mod(q, f.modulus)
		}
		return o
	} else {
		// Regular FFT
		res := f._fft(vals, rootz[0:len(rootz)-1])
		return res
	}
}

func (f *FFT) _fft(vals []*big.Int, roots_of_unity []*big.Int) []*big.Int {
	if len(vals) <= 1 {
		return vals
	}

	roots_of_unity2 := len(roots_of_unity) / 2
	root2 := make([]*big.Int, roots_of_unity2)
	vals_div2 := len(vals) / 2
	for i := 0; i < roots_of_unity2; i++ {
		root2[i] = roots_of_unity[i*2]
	}
	o := make([]*big.Int, len(vals))

	var L []*big.Int
	var R []*big.Int
	if len(vals) >= 1024 {
		var wg sync.WaitGroup
		y_times_root := make([]*big.Int, vals_div2)
		wg.Add(1)
		go func() {
			lvals := make([]*big.Int, vals_div2)
			for i := 0; i < vals_div2; i++ {
				lvals[i] = vals[i*2]
			}
			L = f._fft(lvals, root2)
			wg.Done()
		}()
		wg.Add(1)
		go func() {
			rvals := make([]*big.Int, vals_div2)
			for i := 0; i < vals_div2; i++ {
				rvals[i] = vals[i*2+1]
			}
			R = f._fft(rvals, root2)
			for i, rval := range R {
				y_times_root[i] = new(big.Int).Mul(rval, roots_of_unity[i])
			}
			wg.Done()
		}()
		wg.Wait()

		wg.Add(1)
		go func() {
			t := new(big.Int)
			for i, x := range L {
				t.Add(x, y_times_root[i])
				o[i] = new(big.Int).Mod(t, f.modulus)
			}
			wg.Done()
		}()
		wg.Add(1)
		go func() {
			t := new(big.Int)
			for i, x := range L {
				t.Sub(x, y_times_root[i])
				o[i+len(L)] = new(big.Int).Mod(t, f.modulus)
			}
			wg.Done()
		}()
		wg.Wait()
	} else {
		lvals := make([]*big.Int, vals_div2)
		for i := 0; i < vals_div2; i++ {
			lvals[i] = vals[i*2]
		}
		L = f._fft(lvals, root2)

		rvals := make([]*big.Int, vals_div2)
		for i := 0; i < vals_div2; i++ {
			rvals[i] = vals[i*2+1]
		}
		R = f._fft(rvals, root2)

		y_times_root := new(big.Int)
		t1 := new(big.Int)
		t2 := new(big.Int)
		for i, x := range L {
			y_times_root.Mul(R[i], roots_of_unity[i])
			o[i] = new(big.Int).Mod(t1.Add(x, y_times_root), f.modulus)
			o[i+len(L)] = new(big.Int).Mod(t2.Sub(x, y_times_root), f.modulus)
		}
	}
	return o
}
