package main

// #cgo pkg-config: libcryptsetup
// #include <errno.h>
// #include <stdlib.h>
// #include <libcryptsetup.h>
// void setuplogcb();
import "C"
import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strconv"

	"github.com/darkskiez/u2f-luks/lukstoken/tokenconfig"
	"github.com/darkskiez/u2f-luks/u2fluks"
	"github.com/darkskiez/u2fhost"
)

var u2fFacet = "u2fkeystore://"
var device = flag.String("d", "", "crypt device")

//export golog
func golog(level C.int, msg *C.char) {
	fmt.Printf("Log: %v %v\n", level, C.GoString(msg))
}

func main() {
	flag.Parse()

	C.setuplogcb()
	var cd *C.struct_crypt_device

	_ = C.crypt_init(&cd, C.CString(*device))
	defer func() {
		C.crypt_free(cd)
	}()

	if r := C.crypt_load(cd, C.CString(C.CRYPT_LUKS2), nil); r != 0 {
		fmt.Printf("crypt_load: ret %v\n", r)
		return
	}

	app := u2fhost.NewClient(u2fFacet)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fmt.Printf("Tap Security Key to enroll.\n")
	keydb, passphrase, err := u2fluks.Enroll(ctx, app)
	if err != nil {
		fmt.Printf("Register Failed: %v\n", err)
		return
	}
	fmt.Printf("Touch Registered.\n")

	// TODO ask for and validate existing password before preceeding.
	password := "password"
	/*
		r = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, password, password_len, 0);
		if (r < 0) {
			crypt_safe_memzero(password, password_len);
			free(password);
			crypt_free(cd);
			return r;
		}


	*/

	keyslot := C.crypt_keyslot_add_by_passphrase(cd, C.CRYPT_ANY_SLOT,
		C.CString(password), C.ulong(len(password)),
		C.CString(passphrase), C.ulong(len(passphrase)))
	if keyslot < 0 {
		fmt.Printf("keyslot add failed: errno %v\n", -keyslot)
		return
	}

	fmt.Printf("Registered Keyslot:%v\n", keyslot)
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
	}
	fmt.Printf("Registered Token:%v\n", token)
	return
}
