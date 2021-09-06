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
	keydb, passphrase, err := u2fluks.Enroll(ctx, app)
	if err != nil {
		fmt.Printf("Register Failed: %v\n", err)
		return
	}
	config := tokenconfig.New(keydb)
	tokenjson, err := json.Marshal(config)
	if err != nil {
		fmt.Printf("Json Marshal Failed: %v\n", err)
		return
	}

	/*
		r = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, password, password_len, 0);
		if (r < 0) {
			crypt_safe_memzero(password, password_len);
			free(password);
			crypt_free(cd);
			return r;
		}
	*/

	_ = passphrase
	// TODO REGISTER a keyslot

	//var keyslot C.int = C.CRYPT_ANY_SLOT
	token := C.crypt_token_json_set(cd, C.CRYPT_ANY_TOKEN, C.CString(string(tokenjson)))
	if token < 0 {
		fmt.Printf("crypt_token_json_set: ret %v\n", token)
		fmt.Printf("json: %v\n", string(tokenjson))
	}
	/*
			r := C.crypt_token_assign_keyslot(cd, token, keyslot)
			if r != 0 {
				fmt.Printf("crypt_token_assign_keyslot: ret %v\n", r)
				return
			}

		if r != token {
			C.crypt_token_json_set(cd, token, nil)
			r = C.EINVAL
		}

		_ = r
	*/
}
