package main

// #cgo pkg-config: libcryptsetup
// #cgo LDFLAGS: -Wl,--version-script=crypt.version
// #include <errno.h>
// #include <stdlib.h>
// #include <libcryptsetup.h>
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/darkskiez/u2f-luks/keydb"
	"github.com/darkskiez/u2f-luks/u2fluks"
	"github.com/darkskiez/u2fhost"
)

var ver = C.CString("0.1")
var u2fFacet = "u2fkeystore://"

//export cryptsetup_token_open_pin
func cryptsetup_token_open_pin(cd *C.struct_crypt_device, token C.int, pin *C.char, pinSize C.size_t, password **C.char, password_len *C.size_t, usrptr *C.char) C.int {
	fmt.Println("OPEN PIN %v", C.GoString(pin))
	return -1
}

//export cryptsetup_token_version
func cryptsetup_token_version() *C.char {
	return ver
}

/*
 * @return 0 on success (token passed LUKS2 keyslot passphrase in buffer) or
 *         negative errno otherwise.
 *
 * @note Negative ENOANO errno means that token is PIN protected and caller should
 *       use @link crypt_activate_by_token_pin @endlink with PIN provided.
 *
 * @note Negative EAGAIN errno means token handler requires additional hardware
 *       not present in the system
 */

//export cryptsetup_token_open
func cryptsetup_token_open(cd *C.struct_crypt_device, token C.int, password **C.char, password_len *C.size_t, usrptr *C.char) C.int {
	fmt.Printf("OPEN token:%v usrptr:%v\n", token, usrptr)

	var cjson *C.char

	/* libcryptsetup API call */
	cerr := C.crypt_token_json_get(cd, token, &cjson)
	if cerr < 0 {
		fmt.Printf("     cerr:%v\n", cerr)
		return -cerr
	}
	fmt.Printf("     json:%v\n", C.GoString(cjson))
	var config tokenconfig.TokenConfig
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		fmt.Printf("err:%v", err)
		return -C.EINVAL
	}
	fmt.Printf(" decoded: %#v\n", config)

	key, err := keydb.DecodeString(config.KeyHandle + " " + config.KeyHash)
	if err != nil {
		log.Printf("Load keys failed: %v", err)
		return -C.EINVAL
	}
	keys := keydb.AuthorisedKeys{key}

	app := u2fhost.NewClient(u2fFacet)
	c := make(chan string)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res, err := app.CheckAuthenticate(ctx, keys.KeyHandlers())
	if err != nil {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString(fmt.Sprintf("CheckAuthenticate failed:%v\n", err)))
		return -C.ENOANO
	}
	if !res {
		return -C.ENOANO
	}

	authfunc := func() {
		if len(keys) == 0 {
			c <- ""
			return
		}
		pwd, err := u2fluks.Authorize(ctx, app, keys)
		if err != nil {
			C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString(fmt.Sprintf("Authorize failed:%v\n", err)))
			c <- ""
		} else {
			C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("Touch Registered\n"))
			c <- pwd
		}
	}
	go authfunc()
	pwd := <-c
	if pwd == "" {
		return -C.ENOKEY
	}
	*password = C.CString(pwd)
	*password_len = C.size_t(len(pwd))
	return 0
}

//export cryptsetup_token_dump
func cryptsetup_token_dump(cd *C.struct_crypt_device, cjson *C.char) {
	var config TokenConfig
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString(fmt.Sprintf("Invalid JSON config:%v\n", err)))
		return
	}
	for s := range config.KeySlots {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString(fmt.Sprintf("Unlocks slot:%v\n", s)))
	}
	if config.IDHandle == "" {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("No PIN/Passphrase requirement - or undeclared\n"))
	} else {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("PIN/Passphrase required\n"))
	}
}

//export cryptsetup_token_validate
func cryptsetup_token_validate(cd *C.struct_crypt_device, cjson *C.char) C.int {
	C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("VALIDATE\n"))
	var config TokenConfig
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		fmt.Printf("err:%v", err)
		return -C.EINVAL
	}
	_, err := keydb.DecodeString(config.KeyHandle + " " + config.KeyHash)
	if err != nil {
		fmt.Printf("err:%v", err)
		return -C.EINVAL
	}
	if config.IDHandle != "" {
		_, err := keydb.DecodeString(config.IDHandle + " " + config.KeyHash)
		if err != nil {
			fmt.Printf("err:%v", err)
			return -C.EINVAL
		}
	}

	return 0
}

func main() {
}
