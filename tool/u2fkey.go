package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"crypto/elliptic"

	"github.com/darkskiez/u2f-luks/eckr"
	"github.com/darkskiez/u2f-luks/u2fapp"
)

var u2f_facet string
var keyhandle string
var keyhash string
var keyfile string
var tty bool
var enrollkey bool
var verbose bool

// sha256 hash of app
var app []byte

type AuthorisedKey struct {
	keyHandle, publicKeyHash []byte
}

// KeyHandler interface
func (a AuthorisedKey) KeyHandle() u2fapp.KeyHandle {
	return a.keyHandle
}

var AuthorisedKeys []AuthorisedKey

func init() {
	flag.StringVar(&u2f_facet, "app", "u2fkeystore://", "app id for u2f")
	flag.StringVar(&keyfile, "keyfile", "/etc/u2f-luks.keys", "keyfile")
	flag.StringVar(&keyhandle, "k", "", "key handle")
	flag.StringVar(&keyhash, "h", "", "key hash")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.BoolVar(&tty, "tty", true, "Prompt for a password")
	flag.BoolVar(&enrollkey, "enroll", false, "Enroll a key")
}

func enroll(ctx context.Context, app u2fapp.Client) (*AuthorisedKey, []byte, error) {
	log.Println("Enrolling new key, provide user presence")
	res, err := app.Register(ctx)

	if err != nil {
		return nil, nil, err
	}

	pubKeyX := res.PublicKey[1:33]
	pubKeyY := res.PublicKey[33:65]

	//log.Printf("K  %x %x", pubKeyX, pubKeyY)
	//log.Printf("KH %x", res.KeyHandle)

	// smaller hash output or both keyparts?
	ksum := sha256.Sum256([]byte(pubKeyX))
	//log.Printf("KS %x", ksum)

	ak := &AuthorisedKey{
		keyHandle:     res.KeyHandle,
		publicKeyHash: ksum[:],
	}
	return ak, pubKeyY, nil
}

func authorize(ctx context.Context, app u2fapp.Client, aks []AuthorisedKey) (string, error) {
	// slices of interfaces need converted :(
	khs := make([]u2fapp.KeyHandler, len(aks))
	for i, v := range aks {
		khs[i] = v
	}

	res, err := app.Authenticate(ctx, khs)

	curve := elliptic.P256()
	sig := struct {
		R *big.Int
		S *big.Int
	}{}
	_, err = asn1.Unmarshal(res.Signature, &sig)
	if err != nil {
		return "", err
	}

	data := make([]byte, 69)
	copy(data[:32], app.FacetID[:])
	data[32] = 0x01
	binary.BigEndian.PutUint32(data[33:37], res.Counter)
	copy(data[37:], res.AuthenticateRequest.Challenge)
	sum := sha256.Sum256([]byte(data))

	keys := eckr.RecoverPublicKeys(curve, sum[:], sig.R, sig.S)
	for i := 0; i < 2; i++ {
		dksum := sha256.Sum256([]byte(keys[i].X.Bytes()))
		if bytes.Equal(dksum[:], aks[res.KeyHandleIndex].publicKeyHash) {
			//log.Printf("K:%x %x", keys[i].X, keys[i].Y)
			return fmt.Sprintf("%x", keys[i].Y), nil
		}
	}

	return "", errors.New("Did not match any keys")
}

func promptPassword() (string, error) {
	fmt.Fprintf(os.Stderr, "Touch token or enter password:")
	password, err := terminal.ReadPassword(0)
	return string(password), err
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
			keyHandle:     kh,
			publicKeyHash: pkh,
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
	_, err = fmt.Fprintf(w, "%x %x\n", a.keyHandle, a.publicKeyHash)
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

	if !verbose {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	if flag.NArg() == 1 && flag.Arg(0) != "" {
		keyfile = flag.Arg(0)
	}

	if keyfile != "" {
		log.Printf("Using keyfile: %v", keyfile)
		var err error
		AuthorisedKeys, err = loadKeyfile(keyfile)
		if err != nil {
			log.Printf("Error loading tokens: %v", err)
		}
		log.Printf("Loaded %d tokens", len(AuthorisedKeys))
	}

	ctx := context.Background()
	app := u2fapp.NewClient(u2f_facet)

	if enrollkey {
		ak, _, err := enroll(ctx, app)
		if err != nil {
			log.Fatal(err)
		}
		if keyfile != "" {
			if err := appendKeyfile(keyfile, *ak); err != nil {
				log.Fatal(err)
			}
		}
	} else if len(AuthorisedKeys) == 0 && !tty {
		log.Fatalf("No keys to authenticate, prompt disabled, please enroll some keys")
	} else {
		c := make(chan string)
		if len(AuthorisedKeys) > 0 {
			go func() {
				pwd, _ := authorize(ctx, app, AuthorisedKeys)
				c <- pwd
			}()
		}
		if tty {
			oldState, err := terminal.GetState(0)
			if err != nil {
				log.Fatal("Could not get state of terminal: " + err.Error())
			}
			defer terminal.Restore(0, oldState)

			sigch := make(chan os.Signal, 1)
			signal.Notify(sigch, os.Interrupt)
			go func() {
				for _ = range sigch {
					terminal.Restore(0, oldState)
					os.Exit(1)
				}
			}()
			go func() {
				pwd, _ := promptPassword()
				c <- pwd
			}()
		}
		fmt.Print(<-c)
	}

}
