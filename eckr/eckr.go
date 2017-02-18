package eckr

// Elliptic Curve Public Key Recovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
)

func modSqrt(z *big.Int, curve *elliptic.CurveParams, a *big.Int) *big.Int {
	p := big.NewInt(1)
	p.Add(p, curve.P)

	r := big.NewInt(1)

	for i := p.BitLen() - 1; i > 1; i-- {
		r.Mul(r, r).Mod(r, curve.P)
		if p.Bit(i) > 0 {
			r.Mul(r, a).Mod(r, curve.P)
		}
	}

	z.Set(r)
	return z
}

func PointsFromX(curve *elliptic.CurveParams, x *big.Int) (y, yn *big.Int) {

	y = new(big.Int)
	yn = new(big.Int)

	/* y = x^2 */
	y.Mul(x, x).Mod(y, curve.P)

	/* y = x^2 - 3 */
	y.Sub(y, big.NewInt(3)).Mod(y, curve.P)

	/* y = x^3 - 3x */
	y.Mul(y, x).Mod(y, curve.P)

	/* y = x^3 - 3x + b */
	y.Add(y, curve.B).Mod(y, curve.P)

	modSqrt(y, curve, y)

	yn.Sub(curve.P, y)

	return y, yn
}

func RecoverPublicKeys(curve elliptic.Curve, hash []byte, r, s *big.Int) ([]ecdsa.PublicKey, error) {
	if r.Sign() <= 0 {
		return nil, errors.New("Signature r must be postive")
	}
	if s.Sign() <= 0 {
		return nil, errors.New("Signature s must be postive")
	}

	n := curve.Params().N
	x := new(big.Int).Mod(r, n)
	rp, rn := PointsFromX(curve.Params(), x)

	rinv := new(big.Int).ModInverse(r, n)

	basex, basey := curve.ScalarBaseMult(hash)
	negbasey := new(big.Int).Neg(basey)

	var keys [2]ecdsa.PublicKey

	for i, y := range []*big.Int{rp, rn} {
		psrx, psry := curve.ScalarMult(r, y, s.Bytes())
		subx, suby := curve.Add(psrx, psry, basex, negbasey)
		px, py := curve.ScalarMult(subx, suby, rinv.Bytes())
		keys[i] = ecdsa.PublicKey{Curve: curve, X: px, Y: py}
	}
	return keys[:], nil
}
