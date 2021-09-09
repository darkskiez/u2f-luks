package main

// #cgo pkg-config: libcryptsetup
// #cgo LDFLAGS: -Wl,--version-script=cryptsetup_token.map
// #include <errno.h>
// #include <stdlib.h>
// #include <libcryptsetup.h>
import "C"
import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/darkskiez/u2f-luks/keydb"
	"github.com/darkskiez/u2f-luks/lukstoken/tokenconfig"
	"github.com/darkskiez/u2f-luks/u2fluks"
	"github.com/darkskiez/u2fhost"
)

var ver = C.CString("0.1")
var u2fFacet = "u2fkeystore://"

//export cryptsetup_token_version
func cryptsetup_token_version() *C.char {
	return ver
}

//export cryptsetup_token_open
func cryptsetup_token_open(cd *C.struct_crypt_device, token C.int, password **C.char, password_len *C.size_t, usrptr *C.char) C.int {
	return cryptsetup_token_open_pin(cd, token, nil, 0, password, password_len, usrptr)
}

//export cryptsetup_token_open_pin
func cryptsetup_token_open_pin(cd *C.struct_crypt_device, token C.int, pin *C.char, pinSize C.size_t, password **C.char, password_len *C.size_t, usrptr *C.char) C.int {
	var cjson *C.char

	/* libcryptsetup API call */
	cerr := C.crypt_token_json_get(cd, token, &cjson)
	if cerr < 0 {
		C.crypt_log(cd, C.CRYPT_LOG_ERROR, C.CString(fmt.Sprintf("token get failed: errno %v\n", -cerr)))
		return cerr
	}
	var config tokenconfig.TokenConfig
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		C.crypt_log(cd, C.CRYPT_LOG_ERROR, C.CString(fmt.Sprintf("token json unmarshal failed: %v\n", err)))
		return -C.EINVAL
	}

	key, err := keydb.DecodeString(config.KeyHandle + " " + config.KeyHash)
	if err != nil {
		C.crypt_log(cd, C.CRYPT_LOG_ERROR, C.CString(fmt.Sprintf("token key decode failed: %v\n", err)))
		return -C.EINVAL
	}
	keys := keydb.AuthorisedKeys{key}
	if config.IDHandle != "" {
		idkey, err := keydb.DecodeString(config.IDHandle + " " + config.KeyHash)
		if err == nil {
			keys = append(keys, idkey)
		}
	}

	if pinSize > 0 {
		keys, err = keys.Decrypt(C.GoStringN(pin, C.int(pinSize)))
		if err != nil {
			return -C.EINVAL
		}
	}

	app := u2fhost.NewClient(u2fFacet)
	c := make(chan string)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res, err := u2fluks.Check(ctx, app, keys)

	switch {
	case err == u2fhost.KeyNotFoundError:
		return -C.ENOANO // A key was inserted but didnt match, ask PIN
	case err == u2fhost.NoKeysInsertedError:
		return -C.EINVAL
	case res == 1:
		return -C.ENOANO // ID Key present - Ask for PIN
	}

	authfunc := func() {
		if len(keys) == 0 {
			c <- ""
			return
		}
		pwd, err := u2fluks.Authorize(ctx, app, keys)
		if err != nil {
			C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString(fmt.Sprintf("Authorize failed: %v\n", err)))
			c <- ""
		} else {
			C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("Touch registered\n"))
			c <- pwd
		}
	}
	C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("Tap Security Key\n"))
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
	var config tokenconfig.TokenConfig
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString(fmt.Sprintf("\tInvalid JSON config:%v\n", err)))
		return
	}
	if config.IDHandle == "" {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("\tNo declared PIN / passphrase requirement\n"))
	} else {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("\tPIN / passphrase required\n"))
	}
}

//export cryptsetup_token_validate
func cryptsetup_token_validate(cd *C.struct_crypt_device, cjson *C.char) C.int {
	var config tokenconfig.TokenConfig
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		C.crypt_log(cd, C.CRYPT_LOG_ERROR, C.CString(err.Error()))
		return -C.EINVAL
	}
	_, err := keydb.DecodeString(config.KeyHandle + " " + config.KeyHash)
	if err != nil {
		C.crypt_log(cd, C.CRYPT_LOG_ERROR, C.CString(err.Error()))
		return -C.EINVAL
	}
	if config.IDHandle != "" {
		_, err := keydb.DecodeString(config.IDHandle + " " + config.KeyHash)
		if err != nil {
			C.crypt_log(cd, C.CRYPT_LOG_ERROR, C.CString(err.Error()))
			return -C.EINVAL
		}
	}
	C.crypt_log(cd, C.CRYPT_LOG_DEBUG, C.CString("Validated U2F Token Config.\n"))

	return 0
}

func main() {
}
