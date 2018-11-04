package keydb

import (
	"bufio"
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/darkskiez/u2fhost"
)

type AuthorisedKey struct {
	U2FKeyHandle, PublicKeyHash []byte
}

type AuthorisedKeys []AuthorisedKey

// KeyHandler interface
func (a AuthorisedKey) KeyHandle() u2fhost.KeyHandle {
	return a.U2FKeyHandle
}

func (a AuthorisedKey) String() string {
	return fmt.Sprintf("%x %x", a.U2FKeyHandle, a.PublicKeyHash)
}

func DecodeString(str string) (AuthorisedKey, error) {
	var ak AuthorisedKey
	parts := strings.Split(str, " ")
	if len(parts) < 2 {
		return ak, errors.New("expected two parts")
	}
	kh, err := hex.DecodeString(parts[0])
	if err != nil {
		return ak, err
	}
	pkh, err := hex.DecodeString(parts[1])
	if err != nil {
		return ak, err
	}
	if len(pkh) != 32 {
		return ak, fmt.Errorf("keyhash has wrong length (want: 32, got %v)", len(pkh))
	}

	return AuthorisedKey{
		U2FKeyHandle:  kh,
		PublicKeyHash: pkh,
	}, nil
}

func (a AuthorisedKey) dup() AuthorisedKey {
	var d AuthorisedKey
	d.PublicKeyHash = make([]byte, len(a.PublicKeyHash))
	copy(d.PublicKeyHash, a.PublicKeyHash)
	d.U2FKeyHandle = make([]byte, len(a.U2FKeyHandle))
	copy(d.U2FKeyHandle, a.U2FKeyHandle)
	return d
}

func (a AuthorisedKey) Encrypt(password string) (AuthorisedKey, error) {
	h := sha256.Sum256([]byte(password))
	cipher, err := aes.NewCipher(h[:])
	if err != nil {
		return AuthorisedKey{}, err
	}
	e := a.dup()
	cipher.Encrypt(e.U2FKeyHandle, a.U2FKeyHandle)
	return e, nil
}

func (a AuthorisedKey) Decrypt(password string) (AuthorisedKey, error) {
	h := sha256.Sum256([]byte(password))
	cipher, err := aes.NewCipher(h[:])
	if err != nil {
		return AuthorisedKey{}, err
	}
	e := a.dup()
	cipher.Decrypt(e.U2FKeyHandle, a.U2FKeyHandle)
	return e, nil
}

func (aks AuthorisedKeys) KeyHandlers() []u2fhost.KeyHandler {
	khs := make([]u2fhost.KeyHandler, len(aks))
	for i, v := range aks {
		khs[i] = v
	}
	return khs
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
		ak, err := DecodeString(scanner.Text())
		if err != nil {
			log.Printf("failed to parse: %v (line %v)", err, i)
			continue
		}
		aks = append(aks, ak)
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return aks, scanner.Err()
}

func (a AuthorisedKey) AppendKeyfile(filename string) error {
	w, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer w.Close() // nolint: errcheck
	_, err = fmt.Fprintf(w, "%s\n", a.String())
	if err != nil {
		return err
	}
	return w.Close()
}

func (aks AuthorisedKeys) Decrypt(password string) (AuthorisedKeys, error) {
	var ret AuthorisedKeys
	for _, a := range aks {
		a, err := a.Decrypt(password)
		if err != nil {
			return nil, err
		}
		ret = append(ret, a)
	}
	return ret, nil
}
