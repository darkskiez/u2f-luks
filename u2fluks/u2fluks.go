package u2fluks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"crypto/elliptic"

	"github.com/darkskiez/eckr"
	"github.com/darkskiez/u2f-luks/keydb"
	"github.com/darkskiez/u2fhost"
)

func Enroll(ctx context.Context, app u2fhost.Client) (keydb.AuthorisedKey, []byte, error) {
	res, err := app.Register(ctx)
	if err != nil {
		return keydb.AuthorisedKey{}, nil, err
	}

	pubKeyX := res.PublicKey[1:33]
	pubKeyY := res.PublicKey[33:65]

	// smaller hash output or both keyparts?
	ksum := sha256.Sum256(pubKeyX)

	ak := keydb.AuthorisedKey{
		U2FKeyHandle:  res.KeyHandle,
		PublicKeyHash: ksum[:],
	}
	return ak, pubKeyY, nil
}

func Authorize(ctx context.Context, app u2fhost.Client, aks keydb.AuthorisedKeys) (string, error) {
	res, err := app.Authenticate(ctx, aks.KeyHandlers())
	if err != nil {
		return "", err
	}

	sig, err := res.Signature.ECSignature()
	if err != nil {
		return "", err
	}

	// Calculate the hashsum that was signed
	data := make([]byte, 69)
	copy(data[:32], app.FacetID[:])
	data[32] = 0x01
	binary.BigEndian.PutUint32(data[33:37], res.Counter)
	copy(data[37:], res.AuthenticateRequest.Challenge)
	sum := sha256.Sum256(data)

	// Recover the public keys from the signature and sum
	curve := elliptic.P256()
	keys, err := eckr.RecoverPublicKeys(curve, sum[:], sig.R, sig.S)
	if err != nil {
		return "", err
	}

	// Find which key matches
	for i := 0; i < 2; i++ {
		dksum := sha256.Sum256(keys[i].X.Bytes())
		if bytes.Equal(dksum[:], aks[res.KeyHandleIndex].PublicKeyHash) {
			return fmt.Sprintf("%x", keys[i].Y), nil
		}
	}

	return "", errors.New("Did not match any keys")
}
