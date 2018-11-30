package u2fluks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"crypto/elliptic"

	"github.com/darkskiez/eckr"
	"github.com/darkskiez/u2f-luks/keydb"
	"github.com/darkskiez/u2fhost"
)

func getChallenge() (string, error) {
	challenge := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, challenge)
	return string(challenge), err
}

func encodedOutput(k []byte) string {
	return base64.StdEncoding.EncodeToString(k)
}

// nolint
func key2hash(salt []byte, k *ecdsa.PublicKey) []byte {
	h := sha512.New()
	h.Write(salt)
	h.Write(k.X.Bytes())
	h.Write(k.Y.Bytes())
	return h.Sum(nil)
}

func Enroll(ctx context.Context, app u2fhost.ClientInterface) (keydb.AuthorisedKey, string, error) {
	challenge, err := getChallenge()
	if err != nil {
		return keydb.AuthorisedKey{}, "", fmt.Errorf("Get random challenge failed: %v", err)
	}

	res, err := app.Register(ctx, challenge)
	if err != nil {
		return keydb.AuthorisedKey{}, "", err
	}

	ak := keydb.AuthorisedKey{
		U2FKeyHandle:  res.KeyHandle,
		PublicKeyHash: key2hash(res.KeyHandle, res.PublicKey),
	}
	return ak, encodedOutput(res.PublicKey.Y.Bytes()), nil
}

func Authorize(ctx context.Context, app u2fhost.ClientInterface, aks keydb.AuthorisedKeys) (string, error) {
	challenge, err := getChallenge()
	if err != nil {
		return "", fmt.Errorf("Get random challenge failed: %v", err)
	}

	res, err := app.Authenticate(ctx, challenge, aks.KeyHandlers())
	if err != nil {
		return "", err
	}

	sig, err := res.Signature.ECSignature()
	if err != nil {
		return "", err
	}

	// Calculate the hashsum that was signed
	data := make([]byte, 69)
	copy(data[:32], app.Facet())
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
		dksum := key2hash(aks[res.KeyHandleIndex].KeyHandle(), &keys[i])
		if bytes.Equal(dksum[:], aks[res.KeyHandleIndex].PublicKeyHash) {
			return encodedOutput(keys[i].Y.Bytes()), nil
		}
	}

	return "", errors.New("Did not match any keys")
}
