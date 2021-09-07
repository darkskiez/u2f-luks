package main

// #cgo pkg-config: libcryptsetup
// #include <errno.h>
// #include <stdlib.h>
// #include <string.h>
// #include <libcryptsetup.h>
// void setuplogcb();
import "C"
import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strconv"

	"github.com/darkskiez/u2f-luks/clipassword"
	"github.com/darkskiez/u2f-luks/lukstoken/tokenconfig"
	"github.com/darkskiez/u2f-luks/u2fluks"
	"github.com/darkskiez/u2fhost"
)

var u2fFacet = "u2fkeystore://"
var device = flag.String("d", "", "crypt device")

//export golog
func golog(level C.int, msg *C.char) {
	fmt.Printf("%v", C.GoString(msg))
}

func strerror(errno C.int) string {
	return C.GoString(C.strerror(errno))
}

func main() {
	flag.Parse()
	clipassword.BackupTerminalState()
	C.setuplogcb()
	var cd *C.struct_crypt_device

	_ = C.crypt_init(&cd, C.CString(*device))
	defer func() {
		C.crypt_free(cd)
	}()

	if r := C.crypt_load(cd, C.CString(C.CRYPT_LUKS2), nil); r < 0 {
		fmt.Printf("crypt_load: %v\n", strerror(-r))
		return
	}

	app := u2fhost.NewClient(u2fFacet)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fmt.Printf("Tap Security Key to enroll: ")
	keydb, passphrase, err := u2fluks.Enroll(ctx, app)
	if err != nil {
		fmt.Printf("register failed: %v\n", err)
		return
	}
	fmt.Printf("Touch registered.\n")

	password, err := clipassword.Prompt("Enter any existing passphrase: ")
	fmt.Printf("\nActivating: ")
	if err != nil {
		fmt.Printf("error reading passphrase: %v\n", err)
		return
	}
	r := C.crypt_activate_by_passphrase(cd, nil, C.CRYPT_ANY_SLOT, C.CString(password), C.ulong(len(password)), 0)
	if r < 0 {
		fmt.Printf("error activating with supplied passphrase: %v\n", strerror(-r))
		return
	}
	fmt.Printf("Activated.\n")

	keyslot := C.crypt_keyslot_add_by_passphrase(cd, C.CRYPT_ANY_SLOT,
		C.CString(password), C.ulong(len(password)),
		C.CString(passphrase), C.ulong(len(passphrase)))
	if keyslot < 0 {
		fmt.Printf("keyslot add failed: %v\n", strerror(-keyslot))
		return
	}

	fmt.Printf("Registered Keyslot: %v\n", keyslot)
	config := tokenconfig.New(keydb)
	config.KeySlots = []string{strconv.FormatInt(int64(keyslot), 10)}
	tokenjson, err := json.Marshal(config)
	if err != nil {
		fmt.Printf("Json Marshal Failed: %v\n", err)
		return
	}

	token := C.crypt_token_json_set(cd, C.CRYPT_ANY_TOKEN, C.CString(string(tokenjson)))
	if token < 0 {
		fmt.Printf("crypt_token_json_set: ret %v\n", token)
		fmt.Printf("json: %v\n", string(tokenjson))
		r := C.crypt_keyslot_destroy(cd, keyslot)
		if r < 0 {
			fmt.Printf("Error removing keyslot: %v\n", strerror(-r))
		}
	}
	fmt.Printf("Registered Token: %v\n", token)
	return
}
