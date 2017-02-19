// Package eckr is for Elliptic Curve Public Key Recovery
package eckr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
)

func pointsFromX(curve *elliptic.CurveParams, x *big.Int) (yp, yn *big.Int) {

	y := new(big.Int)
	yp = new(big.Int)
	yn = new(big.Int)

	// y = x^2 - 3
	y.Mul(x, x).Mod(y, curve.P)
	y.Sub(y, big.NewInt(3)).Mod(y, curve.P)

	// y = x^3 - 3x
	y.Mul(y, x).Mod(y, curve.P)

	// y = x^3 - 3x + b
	y.Add(y, curve.B).Mod(y, curve.P)

	yp.ModSqrt(y, curve.P)

	yn.Sub(curve.P, yn)

	return yp, yn
}

// RecoverPublicKeys calculates two public keys that may have signed(r,s) the hash.
func RecoverPublicKeys(curve elliptic.Curve, hash []byte, r, s *big.Int) ([]ecdsa.PublicKey, error) {
	if r.Sign() <= 0 {
		return nil, errors.New("Signature r must be positive")
	}
	if s.Sign() <= 0 {
		return nil, errors.New("Signature s must be positive")
	}

	n := curve.Params().N
	x := new(big.Int).Mod(r, n)
	rp, rn := pointsFromX(curve.Params(), x)

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
