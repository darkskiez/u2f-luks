package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/darkskiez/u2f-luks/clipassword"
	"github.com/darkskiez/u2f-luks/keydb"
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
	clipassword.BackupTerminalState()
}

var keys keydb.AuthorisedKeys

func enroll(ctx context.Context, app u2fhost.Client) {
	fmt.Fprintf(os.Stderr, "Insert or tap key\n")
	ak, k, err := u2fluks.Enroll(ctx, app)
	if err != nil {
		log.Fatal(err)
	}
	pwd, err := clipassword.Prompt("Enter password (optional 2FA):")
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		log.Fatal(err)
	}
	if pwd != "" {
		ak, err = ak.Encrypt(pwd)
		if err != nil {
			log.Fatal(err)
		}
	}
	if keyfile != "" {
		if err := ak.AppendKeyfile(keyfile); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("%v", k)
}

func authorise(ctx context.Context, app u2fhost.Client) {
	clipassword.BackupTerminalState()
	c := make(chan string)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	authfunc := func() {
		if len(keys) == 0 {
			return
		}
		pwd, err := u2fluks.Authorize(cctx, app, keys)
		if err != nil {
			log.Printf("Authorise failed: %v", err)
		} else {
			fmt.Fprintf(os.Stderr, "Touch Registered\n")
			c <- pwd
		}
	}
	go authfunc()
	if tty {
		go func() {
			pwd, err := clipassword.Prompt("Enter password:")
			if err != nil {
				log.Printf("Prompt for password failed: %v", err)
				return
			}
			fmt.Fprintf(os.Stderr, "\nInsert or tap U2F key (enter to cancel)\n")

			keys, err = keys.Decrypt(pwd)
			if err != nil {
				// fallback on returned typed password by itself
				c <- pwd
				return
			}

			// restart u2f auth with new keys
			cancel()
			cctx, cancel = context.WithCancel(ctx)
			defer cancel()
			go authfunc()

			// accept another enter to skip u2f auth
			bufio.NewReader(os.Stdin).ReadBytes('\n')
			fmt.Fprintf(os.Stderr, "U2F Cancelled\n")
			c <- pwd
		}()
	}

	key := <-c
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Print(key)
	clipassword.RestoreTerminalState()
}

func main() {
	flag.Parse()

	if !verbose {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	if keyfile != "" {
		log.Printf("Using keyfile: %v", keyfile)
		var err error
		keys, err = keydb.LoadKeyfile(keyfile)
		if err != nil {
			log.Printf("Error loading keys: %v", err)
		}
		log.Printf("Loaded %d keys", len(keys))
	}

	ctx := context.Background()
	app := u2fhost.NewClient(u2fFacet)

	if enrollkey {
		enroll(ctx, app)
	} else if len(keys) == 0 && !tty {
		log.Fatalf("No keys to authenticate, prompt disabled (enroll some U2F keys)")
	} else {
		authorise(ctx, app)
	}
}
