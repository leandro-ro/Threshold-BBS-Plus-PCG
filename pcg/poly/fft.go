package poly

import (
	"fmt"
	"math"
	"math/big"
	"sync"
)

var (
	ONE = big.NewInt(1)
	TWO = big.NewInt(2)
)

// FrModulus is the modulus of Fr in BLS12-381
const FrModulus = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

// FrPrimitiveRootOfUnity returns a generator for the multiplicative group of scalars.
const FrPrimitiveRootOfUnity = "7"

// FrNthRootOfUnity is the 2^Nth root of unity for FrModulus.
const frN8thRootOfUnity = "8031134342720706638121837972897357960137225421159210873251699151356237587899"
const frN9thRootOfUnity = "43829637617520217940831602274391167521650037592896848111162657113203041232920"
const frN10thRootOfUnity = "12349097598587345001440480015665551665503451720274001758508693314387019426020"
const frN11thRootOfUnity = "42853396751216975442762058439602411095138397255013100628452284779662263622774"
const frN12thRootOfUnity = "39597673698460115882934169648122882883425923233537034756724144574500232944391"
const frN13thRootOfUnity = "2465960250568263762220126882575252149854168204687310190867201213496387481970"
const frN14thRootOfUnity = "9976204341776361977742748423451366288587443230841564489059561418258858231852"
const frN15thRootOfUnity = "42400810780861186701166149563601807998852160029558626092014852995878758418500"
const frN16thRootOfUnity = "15968166010116182336532131851767108014026905997702334713936590815301773565371"
const frN17thRootOfUnity = "23585183866028178652016216032832088239736493004720378936587937039174931251084"
const frN18thRootOfUnity = "6655958292649360769328239839605671205036555777397685393812647748815793627517"
const frN19thRootOfUnity = "51555063808423308049511962493800938964626677430689792843329428329414086596084"
const frN20thRootOfUnity = "40761091479171164124770217649282394772014553669504867428009848071682288518237"
const frN21thRootOfUnity = "14361536881434323440496415919546682220756906901284133287236631717500087413776"

// FFT is a struct that holds the modulus and root of unity to perform FFT with these parameters.
// The FFT code was partly taken over from https://github.com/OlegJakushkin/deepblockchains/blob/81407c2359d6680d25b507b9f4b98b42eb164978/stark/primefield.go
type FFT struct {
	modulus     *big.Int
	rootOfUnity *big.Int
	n           int // n is the maximum number of coefficients of the polynomial given for multiplication.
}

func NewFFT(modulus *big.Int, rootOfUnity *big.Int) (*FFT, error) {
	if modulus == nil || rootOfUnity == nil {
		panic("modulus or rootOfUnity cannot be nil")
	}
	return &FFT{modulus, rootOfUnity, -1}, nil
}

// NewBLS12381FFT creates a new FFT struct with the modulus and root of unity for BLS12-381.
// 2**n is the maximum number of coefficients of the polynomial for multiplication.
func NewBLS12381FFT(n int) (*FFT, error) {
	modulus := new(big.Int)
	modulus.SetString(FrModulus, 16)

	// we need to choose n+1, s.t. all multiplications of polynomials of degree n can be represented.
	n = n + 1

	// Choosing the appropriate root of unity for the +given n is important for the FFT performance.
	rootOfUnity := big.NewInt(0)
	switch {
	case n >= 1 && n <= 8: // For polynomials of degree < 2**8, naive multiplication is generally faster.
		rootOfUnity.SetString(frN8thRootOfUnity, 10)
	case n == 9:
		rootOfUnity.SetString(frN9thRootOfUnity, 10)
	case n == 10:
		rootOfUnity.SetString(frN10thRootOfUnity, 10)
	case n == 11:
		rootOfUnity.SetString(frN11thRootOfUnity, 10)
	case n == 12:
		rootOfUnity.SetString(frN12thRootOfUnity, 10)
	case n == 13:
		rootOfUnity.SetString(frN13thRootOfUnity, 10)
	case n == 14:
		rootOfUnity.SetString(frN14thRootOfUnity, 10)
	case n == 15:
		rootOfUnity.SetString(frN15thRootOfUnity, 10)
	case n == 16:
		rootOfUnity.SetString(frN16thRootOfUnity, 10)
	case n == 17:
		rootOfUnity.SetString(frN17thRootOfUnity, 10)
	case n == 18:
		rootOfUnity.SetString(frN18thRootOfUnity, 10)
	case n == 19:
		rootOfUnity.SetString(frN19thRootOfUnity, 10)
	case n == 20:
		rootOfUnity.SetString(frN20thRootOfUnity, 10)
	case n == 21:
		rootOfUnity.SetString(frN21thRootOfUnity, 10)
	default:
		return nil, fmt.Errorf("n must be between 1 and 21 (inclusive)")
	}

	return &FFT{modulus, rootOfUnity, n}, nil
}

func (f *FFT) MulPolysFFT(a []*big.Int, b []*big.Int) ([]*big.Int, error) {
	maxLen := int(math.Pow(2, float64(f.n)))
	if len(a) > maxLen || len(b) > maxLen {
		panic("polynomial too large")
	}

	x1 := f.fft(a, false)
	x2 := f.fft(b, false)
	c := make([]*big.Int, len(x1))
	t := new(big.Int)
	for i, v1 := range x1 {
		t.Mul(v1, x2[i])
		c[i] = new(big.Int).Mod(t, f.modulus)
	}

	inv := f.fft(c, true)

	result := make([]*big.Int, len(a)+len(b)-1)
	for i := range result {
		result[i] = big.NewInt(0)
		if inv[i] != nil {
			result[i].Set(inv[i])
		}
	}

	return result, nil
}

// ForwardFFT converts a slice of polynomial coefficients (as *big.Int) into its point-value form using FFT.
func (f *FFT) ForwardFFT(coeffs []*big.Int) ([]*big.Int, error) {
	if len(coeffs) > int(math.Pow(2, float64(f.n))) {
		return nil, fmt.Errorf("polynomial too large for FFT parameters")
	}
	pointValues := f.fft(coeffs, false)
	return pointValues, nil
}

// InverseFFT converts a slice of point-values (as *big.Int) back into polynomial coefficients using the inverse FFT.
func (f *FFT) InverseFFT(pointValues []*big.Int) ([]*big.Int, error) {
	if len(pointValues) > int(math.Pow(2, float64(f.n))) {
		return nil, fmt.Errorf("point-value form too large for FFT parameters")
	}
	coeffs := f.fft(pointValues, true)
	return coeffs, nil
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

func (f *FFT) _fft(vals []*big.Int, rootsOfUnity []*big.Int) []*big.Int {
	if len(vals) <= 1 {
		return vals
	}

	rootsOfUnity2 := len(rootsOfUnity) / 2
	root2 := make([]*big.Int, rootsOfUnity2)
	valsDiv2 := len(vals) / 2
	for i := 0; i < rootsOfUnity2; i++ {
		root2[i] = rootsOfUnity[i*2]
	}
	o := make([]*big.Int, len(vals))

	var L []*big.Int
	var R []*big.Int
	if len(vals) >= 1024 {
		var wg sync.WaitGroup
		y_times_root := make([]*big.Int, valsDiv2)
		wg.Add(1)
		go func() {
			lvals := make([]*big.Int, valsDiv2)
			for i := 0; i < valsDiv2; i++ {
				lvals[i] = vals[i*2]
			}
			L = f._fft(lvals, root2)
			wg.Done()
		}()
		wg.Add(1)
		go func() {
			rvals := make([]*big.Int, valsDiv2)
			for i := 0; i < valsDiv2; i++ {
				rvals[i] = vals[i*2+1]
			}
			R = f._fft(rvals, root2)
			for i, rval := range R {
				y_times_root[i] = new(big.Int).Mul(rval, rootsOfUnity[i])
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
		lvals := make([]*big.Int, valsDiv2)
		for i := 0; i < valsDiv2; i++ {
			lvals[i] = vals[i*2]
		}
		L = f._fft(lvals, root2)

		rvals := make([]*big.Int, valsDiv2)
		for i := 0; i < valsDiv2; i++ {
			rvals[i] = vals[i*2+1]
		}
		R = f._fft(rvals, root2)

		y_times_root := new(big.Int)
		t1 := new(big.Int)
		t2 := new(big.Int)
		for i, x := range L {
			y_times_root.Mul(R[i], rootsOfUnity[i])
			o[i] = new(big.Int).Mod(t1.Add(x, y_times_root), f.modulus)
			o[i+len(L)] = new(big.Int).Mod(t2.Sub(x, y_times_root), f.modulus)
		}
	}
	return o
}
