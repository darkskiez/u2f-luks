package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func recoverPubkeys(curve elliptic.Curve, hash []byte, sigr, sigs *big.Int) {
	/*
	   	Rp, Rn = curve.points_at_x(curve.i2fe(r))

	   	r, = ec.modp(curve.n, r)
	   	rinv = 1 / r

	   	for R in (Rp, Rn):
	     	  p = curve.point_mul(int(rinv), curve.point_sub(curve.point_mul(s, R), curve.base_mul(e)))
	*/
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

	/*
		k, Q = ec.nistp256.generate_key()
		print 'pub', Q
		msg = 'hello world'
		sig = sign(ec.nistp256, H, k, msg)
		verify(ec.nistp256, H, Q, msg, sig)

		points = recover_candidate_pubkeys(ec.nistp256, H, msg, sig)
	*/

}
