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
	if sigr.Sign() <= 0 {
		fmt.Errorf("SigR must be postive")
	}
	if sigs.Sign() <= 0 {
		fmt.Errorf("SigS must be postive")
	}
	fmt.Printf("r:%x\ns:%x\n", sigr, sigs)

	n := curve.Params().N

	x := new(big.Int).Mod(sigr, n)
	rp, rn := PointsFromX2(curve.Params(), x)

	fmt.Printf("Rp:%x\nRn:%x\n", rp, rn)
	e := new(big.Int)
	err := e.GobDecode(hash)
	if err != nil {
		fmt.Errorf("GobDecode failed")
	}
	//one := new(big.Int).SetInt64(1)

	einv := new(big.Int)
	einv.Sub(einv, e)
	einv.Mod(einv, n)

	rinv := new(big.Int).ModInverse(sigr, n)
	fmt.Printf("rinv: %x\n", rinv)

	basex, basey := curve.ScalarBaseMult(hash)
	fmt.Printf("base: %x %x\n", basex, basey)
	negbasey := new(big.Int).Neg(basey)

	psrx, psry := curve.ScalarMult(sigr, rp, sigs.Bytes())
	fmt.Printf("psr: %x %x\n", psrx, psry)

	subx, suby := curve.Add(psrx, psry, basex, negbasey)
	fmt.Printf("sub: %x %x\n", subx, suby)

	px, py := curve.ScalarMult(subx, suby, rinv.Bytes())
	fmt.Printf("p: %x %x\n", px, py)

	//q :=  curve.
	/*
		   	Rp, Rn = curve.points_at_x(r % curve.Params().N)

		   	r, = ec.modp(curve.n, r)
		   	rinv = 1 / r

		   	for R in (Rp, Rn):
		     	  p = curve.point_mul(int(rinv),
				       curve.point_sub(curve.point_mul(s, R), curve.base_mul(hash)))
	*/

	//curve.Add(x1,y1,x2,y2)
	//xe, ye := curve.ScalarBaseMult(hashToInt(hash, curve))
	//xf, yf := curve.ScalarMult(x, y1, sigr)
	//curve.Add(xf,yf,-xe,ye)

	//curve.ScalarMult(x, y1, rinv)
}

func main() {
	ec := elliptic.P256()
	msg := "hello world"
	//k 52aa4c83ddbc0131f671d3d69a49c7995c558a5834d82f679bdd3fb338539a4d
	//pub <point 0xb05e0deeee51b52956eff8034ffbc09a5331143114c1fb1c82705504f978370a, 0x2ee7efa2467fec9d0b8f7a860503919decb0bad76bc797bf482e95254e226fcc>
	//hash  0xb94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9L

	sigr, _ := new(big.Int).SetString("350b1572ff1b72831383c1d7c15c5aba106d62af007551d22bd313f25b1dfba8", 16)
	sigs, _ := new(big.Int).SetString("bf58baa28d760df87db5e069bd2dde2080d4dbd03cd76421bdcd1cc58c82ae69", 16)

	pubx, _ := new(big.Int).SetString("b05e0deeee51b52956eff8034ffbc09a5331143114c1fb1c82705504f978370a", 16)
	puby, _ := new(big.Int).SetString("2ee7efa2467fec9d0b8f7a860503919decb0bad76bc797bf482e95254e226fcc", 16)

	pubkey := &ecdsa.PublicKey{Curve: ec, X: pubx, Y: puby}

	sum := sha256.Sum256([]byte(msg))
	fmt.Printf("hash %x\n", sum[:])

	ver := ecdsa.Verify(pubkey, sum[:], sigr, sigs)
	fmt.Printf("%+v\n", ver)

	y1, y2 := PointsFromX2(ec.Params(), pubx)
	fmt.Printf("puby:%+v\ny1:%+v\ny2:%+v\n", puby.Text(16), y1.Text(16), y2.Text(16))

	recoverPubkeys(ec, sum[:], sigr, sigs)

	/*
		k, Q = ec.nistp256.generate_key()
		print 'pub', Q
		msg = 'hello world'
		sig = sign(ec.nistp256, H, k, msg)
		verify(ec.nistp256, H, Q, msg, sig)

		points = recover_candidate_pubkeys(ec.nistp256, H, msg, sig)
	*/

}
