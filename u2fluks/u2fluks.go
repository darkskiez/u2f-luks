package u2fluks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"crypto/elliptic"

	"github.com/darkskiez/eckr"
	"github.com/darkskiez/u2fhost"
)

type AuthorisedKey struct {
	U2FKeyHandle, PublicKeyHash []byte
}

// KeyHandler interface
func (a AuthorisedKey) KeyHandle() u2fhost.KeyHandle {
	return a.U2FKeyHandle
}

type AuthorisedKeys []AuthorisedKey

func (aks AuthorisedKeys) KeyHandlers() []u2fhost.KeyHandler {
	khs := make([]u2fhost.KeyHandler, len(aks))
	for i, v := range aks {
		khs[i] = v
	}
	return khs
}

var savedAuthorisedKeys AuthorisedKeys

func Enroll(ctx context.Context, app u2fhost.Client) (*AuthorisedKey, []byte, error) {
	res, err := app.Register(ctx)

	if err != nil {
		return nil, nil, err
	}

	pubKeyX := res.PublicKey[1:33]
	pubKeyY := res.PublicKey[33:65]

	//log.Printf("K  %x %x", pubKeyX, pubKeyY)
	//log.Printf("KH %x", res.KeyHandle)

	// smaller hash output or both keyparts?
	ksum := sha256.Sum256(pubKeyX)
	//log.Printf("KS %x", ksum)

	ak := &AuthorisedKey{
		U2FKeyHandle:  res.KeyHandle,
		PublicKeyHash: ksum[:],
	}
	return ak, pubKeyY, nil
}

func Authorize(ctx context.Context, app u2fhost.Client, aks AuthorisedKeys) (string, error) {
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

func LoadKeyfile(filename string) (AuthorisedKeys, error) {
	aks := make([]AuthorisedKey, 0, 10)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close() // nolint: errcheck

	scanner := bufio.NewScanner(file)
	i := 0
	for scanner.Scan() {
		i++
		parts := strings.Split(scanner.Text(), " ")
		if len(parts) < 2 {
			log.Printf("failed to parse: %v (line %v)", err, i)
			continue
		}
		kh, err := hex.DecodeString(parts[0])
		if err != nil {
			log.Printf("failed to decode keyhandle %v (line %v)", err, i)
			continue
		}
		pkh, err := hex.DecodeString(parts[1])
		if err != nil {
			log.Printf("failed to decode keyhash %v (line %v)", err, i)
			continue
		}
		if len(pkh) != 32 {
			log.Fatalf("keyhash has wrong length %v (expected: 32) (line %v)", len(pkh), i)
			continue
		}

		aks = append(aks, AuthorisedKey{
			U2FKeyHandle:  kh,
			PublicKeyHash: pkh,
		})
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return aks, scanner.Err()
}

func AppendKeyfile(filename string, a AuthorisedKey) error {
	w, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer w.Close() // nolint: errcheck
	_, err = fmt.Fprintf(w, "%x %x\n", a.U2FKeyHandle, a.PublicKeyHash)
	if err != nil {
		return err
	}
	return w.Close()
}

func DecryptKeyHandles(password string, aks AuthorisedKeys) (AuthorisedKeys, error) {
	ret := aks
	h := sha256.Sum256([]byte(password))
	cipher, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, err
	}
	for _, a := range aks {
		cipher.Decrypt(a.U2FKeyHandle, a.U2FKeyHandle)
		ret = append(ret, a)
	}
	return ret, nil
}
