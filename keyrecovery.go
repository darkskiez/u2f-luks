package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Compute a = sqrt(a) (mod curve_p).
// https://github.com/kmackay/micro-ecc/blob/1fce01e69c3f3c179cb9b6238391307426c5e887/uECC.c#L1685
func modSqrt(z *big.Int, curve *elliptic.CurveParams, a *big.Int) *big.Int {
	p1 := big.NewInt(1)
	p1.Add(p1, curve.P)

	result := big.NewInt(1)

	for i := p1.BitLen() - 1; i > 1; i-- {
		result.Mul(result, result)
		result.Mod(result, curve.P)
		if p1.Bit(i) > 0 {
			result.Mul(result, a)
			result.Mod(result, curve.P)
		}
	}

	z.Set(result)
	return z
}

func PointsFromX2(curve *elliptic.CurveParams, x *big.Int) (y, yn *big.Int) {

	y = new(big.Int)
	yn = new(big.Int)

	/* y = x^2 */
	y.Mul(x, x)
	y.Mod(y, curve.P)

	/* y = x^2 - 3 */
	y.Sub(y, big.NewInt(3))
	y.Mod(y, curve.P)

	/* y = x^3 - 3x */
	y.Mul(y, x)
	y.Mod(y, curve.P)

	/* y = x^3 - 3x + b */
	y.Add(y, curve.B)
	y.Mod(y, curve.P)

	modSqrt(y, curve, y)

	yn.Sub(curve.P, y)

	return y, yn
}

/*
rhs = x ** 3 + x * self.a + self.b
y = rhs.sqrt()
return point.xy(int(x), int(y)), point.xy(int(x), -int(y))
*/

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func recoverPubkeys(curve elliptic.Curve, hash []byte, sigr, sigs *big.Int) {
	/*
		   	Rp, Rn = curve.points_at_x(r % curve.Params().N)

		   	r, = ec.modp(curve.n, r)
		   	rinv = 1 / r

		   	for R in (Rp, Rn):
		     	  p = curve.point_mul(int(rinv),
				       curve.point_sub(curve.point_mul(s, R), curve.base_mul(hash)))
	*/

	x := new(big.Int)
	x.Mod(sigr, curve.Params().N)

	y1, y2 = PointsFromX2(curve.Params(), x)

	one := new(big.Int).SetInt64(1)
	rinv := new(big.Int).Div(one, x)

	//curve.Add(x1,y1,x2,y2)
	xe, ye := curve.ScalarBaseMult(hashToInt(hash, curve))
	xf, yf := curve.ScalarMult(x, y1, sigr)
	//curve.Add(xf,yf,-xe,ye)

	curve.ScalarMult(x, y1, rinv)

}

func main() {
	ec := elliptic.P256()
	msg, _ := new(big.Int).SetString("e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3", 16)
	sigr, _ := new(big.Int).SetString("bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f", 16)
	sigs, _ := new(big.Int).SetString("17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c", 16)

	pubx, _ := new(big.Int).SetString("e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c", 16)
	puby, _ := new(big.Int).SetString("970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927", 16)

	pubkey := &ecdsa.PublicKey{Curve: ec, X: pubx, Y: puby}

	sum := sha256.Sum256(msg.Bytes())

	ver := ecdsa.Verify(pubkey, sum[:], sigr, sigs)
	fmt.Printf("%+v", ver)

	y1, y2 := pointsAtX(ec.Params(), pubx)
	fmt.Printf("puby:%+v\ny1:%+v\ny2:%+v", puby.Text(16), y1.Text(16), y2.Text(16))

	y1, y2 = PointsFromX2(ec.Params(), pubx)
	fmt.Printf("puby:%+v\ny1:%+v\ny2:%+v", puby.Text(16), y1.Text(16), y2.Text(16))
	/*
		k, Q = ec.nistp256.generate_key()
		print 'pub', Q
		msg = 'hello world'
		sig = sign(ec.nistp256, H, k, msg)
		verify(ec.nistp256, H, Q, msg, sig)

		points = recover_candidate_pubkeys(ec.nistp256, H, msg, sig)
	*/

}
