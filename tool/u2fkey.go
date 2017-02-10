package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"crypto/elliptic"

	"github.com/darkskiez/u2f-luks/eckr"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

var u2f_app string
var keyhandle string
var keyhash string
var tty bool
var enrollkey bool

// sha256 hash of app
var app []byte

type AuthorisedKey struct {
	KeyHandle, PublicKeyHash []byte
}

var AuthorisedKeys []AuthorisedKey

func init() {
	flag.StringVar(&u2f_app, "app", "u2fkeystore://", "app id for u2f")
	flag.StringVar(&keyhandle, "k", "", "key handle")
	flag.StringVar(&keyhash, "h", "", "key hash")
	flag.BoolVar(&tty, "tty", true, "Prompt for a password")
	flag.BoolVar(&enrollkey, "enroll", false, "Enroll a key")
}

func enroll(t *u2ftoken.Token) (AuthorisedKey, []byte) {
	challenge := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)
	app := sha256.Sum256([]byte(u2f_app))

	var res []byte
	var err error
	log.Println("Enrolling new key, provide user presence")
	for {
		res, err = t.Register(u2ftoken.RegisterRequest{Challenge: challenge, Application: app[:]})
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			log.Fatal(err)
		}
		break
	}

	//log.Printf("registered: %x", res)
	// CHECk RSVD 0x05
	// CHECK PUBKEY TYPE 0x04
	pubKeyX := res[2:34]
	pubKeyY := res[34:66]

	res = res[66:]
	khLen := int(res[0])
	res = res[1:]
	keyHandle := res[:khLen]
	log.Printf("K  %x %x", pubKeyX, pubKeyY)
	log.Printf("KH %x", keyHandle)

	// smaller hash output or both keyparts?
	ksum := sha256.Sum256([]byte(pubKeyX))
	log.Printf("KS %x", ksum)

	ak := AuthorisedKey{
		KeyHandle:     keyHandle,
		PublicKeyHash: ksum[:],
	}
	return ak, pubKeyY
}

func authorize(t *u2ftoken.Token, aks []AuthorisedKey) {
	challenge := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)
	app := sha256.Sum256([]byte(u2f_app))

	/*
		for i, ak := range aks {
			req := u2ftoken.AuthenticateRequest{
				Challenge:   challenge,
				Application: app[:],
				KeyHandle:   kh,
			}
			if err := t.CheckAuthenticate(req); err == nil {
				break
			}
		}
	*/

	log.Println("Authenticating Key, provide user presence")

	var err error
	var res *u2ftoken.AuthenticateResponse
	keyIndex := -1
	for {
		keyIndex = (keyIndex + 1) % len(aks)
		io.ReadFull(rand.Reader, challenge)
		req := u2ftoken.AuthenticateRequest{
			Challenge:   challenge,
			Application: app[:],
			KeyHandle:   aks[keyIndex].KeyHandle,
		}
		res, err = t.Authenticate(req)
		if err == u2ftoken.ErrUnknownKeyHandle || err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			log.Fatal(err)
		}
		break
	}

	//log.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
	curve := elliptic.P256()
	sig := struct {
		R *big.Int
		S *big.Int
	}{}
	_, err = asn1.Unmarshal(res.Signature, &sig)
	//log.Printf("Sig: %+v", sig)
	if err != nil {
		log.Fatal(err)
	}

	data := make([]byte, 69)
	copy(data[:32], app[:])
	data[32] = 0x01
	binary.BigEndian.PutUint32(data[33:37], res.Counter)
	copy(data[37:], challenge)
	sum := sha256.Sum256([]byte(data))

	keys := eckr.RecoverPublicKeys(curve, sum[:], sig.R, sig.S)
	for i := 0; i < 2; i++ {
		dksum := sha256.Sum256([]byte(keys[i].X.Bytes()))
		if bytes.Equal(dksum[:], aks[keyIndex].PublicKeyHash) {
			log.Printf("K:%x %x", keys[i].X, keys[i].Y)
			fmt.Printf("%x\n", keys[i].Y)
			break
		}
	}

}

func loadKeyfile(filename string) ([]AuthorisedKey, error) {
	aks := make([]AuthorisedKey, 0, 10)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	i := 0
	for scanner.Scan() {
		i++
		parts := strings.Split(scanner.Text(), " ")
		if len(parts) < 2 {
			log.Printf("failed to parse (line %v)", err, i)
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
			log.Fatal("keyhash has wrong length %v (expected: 32) (line %v)", len(pkh), i)
			continue
		}

		aks = append(aks, AuthorisedKey{
			KeyHandle:     kh,
			PublicKeyHash: pkh,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return aks, nil
}

func appendKeyfile(filename string, a AuthorisedKey) error {
	w, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer w.Close()
	_, err = fmt.Fprintf(w, "%x %x\n", a.KeyHandle, a.PublicKeyHash)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()
	if flag.NArg() > 1 {
		log.Fatal("Only one keyfile may be supplied as an argument")
	}

	var keyFile string
	if flag.NArg() == 1 {
		keyFile = flag.Arg(0)
		log.Printf("Using keyfile: %v", keyFile)
		var err error
		AuthorisedKeys, err = loadKeyfile(keyFile)
		if err != nil {
			log.Printf("Error loading tokens: %v", err)
		}
		log.Printf("Loaded %d tokens", len(AuthorisedKeys))
	}

	devices, err := u2fhid.Devices()
	if err != nil {
		log.Fatal(err)
	}
	if len(devices) == 0 {
		log.Fatal("no U2F tokens found")
	}

	d := devices[0]
	log.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x", d.Manufacturer, d.Product, d.ProductID, d.VendorID)

	dev, err := u2fhid.Open(d)
	if err != nil {
		log.Fatal(err)
	}
	t := u2ftoken.NewToken(dev)

	version, err := t.Version()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("version:", version)

	if enrollkey {
		ak, key := enroll(t)
		log.Println("kf1")
		if keyFile != "" {
			log.Println("kf2")
			if err := appendKeyfile(keyFile, ak); err != nil {
				log.Fatal(err)
			}
		}
		fmt.Printf("%x", key)
	} else if len(AuthorisedKeys) > 0 {
		authorize(t, AuthorisedKeys)
	} else {
		log.Printf("No keys to authenticate and enroll flag not set")
	}

}
