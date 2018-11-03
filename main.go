package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"crypto/elliptic"

	"github.com/darkskiez/eckr"
	"github.com/darkskiez/u2fhost"
)

var (
	u2fFacet  string
	keyfile   string
	verbose   bool
	tty       bool
	enrollkey bool
)

func init() {
	flag.StringVar(&u2fFacet, "app", "u2fkeystore://", "app id for u2f")
	flag.StringVar(&keyfile, "keyfile", "/etc/u2f-luks.keys", "keyfile")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.BoolVar(&tty, "tty", true, "Prompt for a password")
	flag.BoolVar(&enrollkey, "enroll", false, "Enroll a key")
}

type authorisedKey struct {
	keyHandle, publicKeyHash []byte
}

// KeyHandler interface
func (a authorisedKey) KeyHandle() u2fhost.KeyHandle {
	return a.keyHandle
}

type authorisedKeys []authorisedKey

func (aks authorisedKeys) KeyHandlers() []u2fhost.KeyHandler {
	khs := make([]u2fhost.KeyHandler, len(aks))
	for i, v := range aks {
		khs[i] = v
	}
	return khs
}

var savedAuthorisedKeys authorisedKeys

func enroll(ctx context.Context, app u2fhost.Client) (*authorisedKey, []byte, error) {
	log.Println("Enrolling new key, provide user presence.")
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

	ak := &authorisedKey{
		keyHandle:     res.KeyHandle,
		publicKeyHash: ksum[:],
	}
	return ak, pubKeyY, nil
}

func authorize(ctx context.Context, app u2fhost.Client, aks authorisedKeys) (string, error) {
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
		if bytes.Equal(dksum[:], aks[res.KeyHandleIndex].publicKeyHash) {
			return fmt.Sprintf("%x", keys[i].Y), nil
		}
	}

	return "", errors.New("Did not match any keys")
}

var oldState *terminal.State

func backupTerminalState() {
	var err error
	oldState, err = terminal.GetState(0)
	if err != nil {
		log.Print("Could not get state of terminal: " + err.Error())
		return
	}

	// Dont leave terminal broken on ctrl-c
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	go func() {
		for sig := range sigch {
			if sig != nil {
				restoreTerminalState()
				os.Exit(1)
			}
		}
	}()
}

func restoreTerminalState() {
	if oldState != nil {
		if err := terminal.Restore(0, oldState); err != nil {
			panic("Could not restore terminal:" + err.Error())
		}
	}
}

func promptPassword(prompt string) (string, error) {
	if _, err := fmt.Fprintf(os.Stderr, prompt); err != nil {
		return "", err
	}
	password, err := terminal.ReadPassword(0)
	return string(password), err
}

func loadKeyfile(filename string) (authorisedKeys, error) {
	aks := make([]authorisedKey, 0, 10)

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

		aks = append(aks, authorisedKey{
			keyHandle:     kh,
			publicKeyHash: pkh,
		})
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return aks, scanner.Err()
}

func appendKeyfile(filename string, a authorisedKey) error {
	w, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer w.Close() // nolint: errcheck
	_, err = fmt.Fprintf(w, "%x %x\n", a.keyHandle, a.publicKeyHash)
	if err != nil {
		return err
	}
	return w.Close()
}

func decryptKeyHandles(password string, aks authorisedKeys) (authorisedKeys, error) {
	ret := aks
	h := sha256.Sum256([]byte(password))
	cipher, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, err
	}
	for _, a := range aks {
		cipher.Decrypt(a.keyHandle, a.keyHandle)
		ret = append(ret, a)
	}
	return ret, nil
}

func enrollNewKey(ctx context.Context, app u2fhost.Client) {
	fmt.Fprintf(os.Stderr, "Insert or tap key")
	ak, k, err := enroll(ctx, app)
	if err != nil {
		log.Fatal(err)
	}
	pwd, err := promptPassword("Enter password (optional 2FA):")
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		log.Fatal(err)
	}
	if pwd != "" {
		log.Printf("Encrypting keydata")
		h := sha256.Sum256([]byte(pwd))
		cipher, err := aes.NewCipher(h[:])
		if err != nil {
			log.Fatal(err)
		}
		cipher.Encrypt(ak.keyHandle, ak.keyHandle)
	}
	if keyfile != "" {
		if err := appendKeyfile(keyfile, *ak); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("%x", k)

}

func AuthoriseWithToken(ctx context.Context, app u2fhost.Client) {
	backupTerminalState()
	c := make(chan string)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	authfunc := func() {
		if len(savedAuthorisedKeys) == 0 {
			return
		}
		pwd, err := authorize(cctx, app, savedAuthorisedKeys)
		if err != nil {
			log.Printf("Authorise failed: %v", err)
		} else {
			c <- pwd
		}
	}
	go authfunc()
	if tty {
		go func() {
			pwd, err := promptPassword("Enter password:")
			if err != nil {
				log.Printf("Prompt for password failed: %v", err)
				return
			}
			fmt.Fprintf(os.Stderr, "\nInsert or tap U2F key (enter to cancel)\n")

			savedAuthorisedKeys, err = decryptKeyHandles(pwd, savedAuthorisedKeys)
			if err != nil {
				// fallback on returned typed password by itself
				c <- pwd
				return
			}

			// restart u2f auth with new keys
			cancel()
			cctx, cancel = context.WithCancel(ctx)
			go authfunc()

			// accept another enter to skip u2f auth
			bufio.NewReader(os.Stdin).ReadBytes('\n')
			c <- pwd
		}()
	}
	fmt.Print(<-c)
	restoreTerminalState()
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
		savedAuthorisedKeys, err = loadKeyfile(keyfile)
		if err != nil {
			log.Printf("Error loading keys: %v", err)
		}
		log.Printf("Loaded %d keys", len(savedAuthorisedKeys))
	}

	ctx := context.Background()
	app := u2fhost.NewClient(u2fFacet)

	if enrollkey {
		enrollNewKey(ctx, app)
	} else if len(savedAuthorisedKeys) == 0 && !tty {
		log.Fatalf("No keys to authenticate, prompt disabled (enroll some U2F keys)")
	} else {
		AuthoriseWithToken(ctx, app)
	}
}
