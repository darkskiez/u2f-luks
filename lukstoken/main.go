package main

// #cgo pkg-config: libcryptsetup
// #cgo LDFLAGS: -Wl,--version-script=crypt.version
// #include <errno.h>
// #include <stdlib.h>
// #include <libcryptsetup.h>
import "C"
import (
	"encoding/json"
	"fmt"
)

var ver = C.CString("0.1")

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
type TokenConfig struct {
	Tokentype string `json:"type"`
	Keyslots  []string
	Keyhandle string
	Keyhash   string
}

//export cryptsetup_token_open
func cryptsetup_token_open(cd *C.struct_crypt_device, token C.int, password **C.char, password_len *C.size_t, usrptr *C.char) C.int {
	fmt.Printf("OPEN token:%v usrptr:%v\n", token, usrptr)

	var cjson *C.char

	/* libcryptsetup API call */
	cerr := C.crypt_token_json_get(cd, token, &cjson)
	fmt.Printf("     cerr:%v\n", cerr)
	if cerr != 0 {
		return -1
	}
	fmt.Printf("     json:%v\n", C.GoString(cjson))
	var config TokenConfig
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		fmt.Printf("err:%v", err)
		return -2
	}
	return -C.ENOANO
	fmt.Printf(" decoded: %#v\n", config)
	pwd := C.CString("password")
	*password = pwd
	*password_len = 8
	return 0
}

//export cryptsetup_token_dump
func cryptsetup_token_dump(cd *C.struct_crypt_device, cjson *C.char) {
	C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString("Hello U2F\n"))
	//C.crypt_log(cd, C.CRYPT_LOG_DEBUG_JSON, C.CString("WOO\n"))
}

//export cryptsetup_token_validate
func cryptsetup_token_validate(cd *C.struct_crypt_device, cjson *C.char) C.int {
	fmt.Println("VALIDATE")
	return 0
}

func main() {
	fmt.Println("u2f-token")
}
