package eckr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestEckr(t *testing.T) {
	ec := elliptic.P256()
	msg := "hello world"
	r, _ := new(big.Int).SetString("350b1572ff1b72831383c1d7c15c5aba106d62af007551d22bd313f25b1dfba8", 16)
	s, _ := new(big.Int).SetString("bf58baa28d760df87db5e069bd2dde2080d4dbd03cd76421bdcd1cc58c82ae69", 16)
	x, _ := new(big.Int).SetString("b05e0deeee51b52956eff8034ffbc09a5331143114c1fb1c82705504f978370a", 16)
	y, _ := new(big.Int).SetString("2ee7efa2467fec9d0b8f7a860503919decb0bad76bc797bf482e95254e226fcc", 16)
	pubkey := &ecdsa.PublicKey{Curve: ec, X: x, Y: y}

	sum := sha256.Sum256([]byte(msg))
	if !ecdsa.Verify(pubkey, sum[:], r, s) {
		t.Fatalf("Could not validate ecdsa signature with test data")
	}

	keys, err := RecoverPublicKeys(ec, sum[:], r, s)

	if err != nil {
		t.Fatalf("error: ", err)
	}
	if keys[0].X.Cmp(x) != 0 {
		t.Fatalf("Did not derive public key X %x != %x", keys[0].X, x)
	}
	if keys[0].Y.Cmp(y) != 0 {
		t.Fatalf("Did not derive public key Y %x != %x", keys[0].Y, y)
	}

}
