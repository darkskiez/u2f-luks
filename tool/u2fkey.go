package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"time"

	"crypto/elliptic"

	"github.com/darkskiez/u2f-luks/eckr"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

var u2f_app string
var keyhandle string
var keyhash string

// sha256 hash of app
var app []byte

func init() {
	flag.StringVar(&u2f_app, "app", "u2fkeystore://", "app id for u2f")
	flag.StringVar(&keyhandle, "k", "", "key handle")
	flag.StringVar(&keyhash, "h", "", "key hash")
}

func enroll(t *u2ftoken.Token) {
	challenge := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)
	app := sha256.Sum256([]byte(u2f_app))

	var res []byte
	var err error
	log.Println("registering, provide user presence")
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

	fmt.Printf("-k %s -h %s\n",
		base64.URLEncoding.EncodeToString(keyHandle),
		base64.URLEncoding.EncodeToStrin(ksum))
}

func authorize(t *u2ftoken.Token) {
	challenge := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)
	app := sha256.Sum256([]byte(u2f_app))

	kh, err := hex.DecodeString(keyhandle)
	if err != nil {
		log.Fatal("Failed to decode keyhandle flag %v", err)
	}

	req := u2ftoken.AuthenticateRequest{
		Challenge:   challenge,
		Application: app[:],
		KeyHandle:   kh,
	}
	if err := t.CheckAuthenticate(req); err != nil {
		log.Fatal(err)
	}

	io.ReadFull(rand.Reader, challenge)
	log.Println("authenticating, provide user presence")

	var res *u2ftoken.AuthenticateResponse

	for {
		res, err = t.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
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

	ksum, err := hex.DecodeString(keyhash)
	if err != nil {
		log.Fatal("Could not hex decode key keyhash: %v", err)
	}
	if len(ksum) != 32 {
		log.Fatal("keyhash has wrong length %v != 32", len(ksum))
	}

	for i := 0; i < 2; i++ {
		dksum := sha256.Sum256([]byte(keys[i].X.Bytes()))
		if bytes.Equal(dksum[:], ksum[:]) {
			log.Printf("K:%x %x", keys[i].X, keys[i].Y)
			fmt.Printf("%x%x\n", keys[i].X, keys[i].Y)
			break
		}
	}

}

func main() {
	flag.Parse()

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

	if keyhandle == "" {
		enroll(t)
	} else {
		authorize(t)
	}

}
