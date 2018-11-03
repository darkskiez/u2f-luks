package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/darkskiez/u2f-luks/u2fluks"
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

var savedAuthorisedKeys u2fluks.AuthorisedKeys

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

func enrollNewKey(ctx context.Context, app u2fhost.Client) {
	fmt.Fprintf(os.Stderr, "Insert or tap key")
	ak, k, err := u2fluks.Enroll(ctx, app)
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
		cipher.Encrypt(ak.U2FKeyHandle, ak.U2FKeyHandle)
	}
	if keyfile != "" {
		if err := u2fluks.AppendKeyfile(keyfile, *ak); err != nil {
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
		pwd, err := u2fluks.Authorize(cctx, app, savedAuthorisedKeys)
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

			savedAuthorisedKeys, err = u2fluks.DecryptKeyHandles(pwd, savedAuthorisedKeys)
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
		savedAuthorisedKeys, err = u2fluks.LoadKeyfile(keyfile)
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
