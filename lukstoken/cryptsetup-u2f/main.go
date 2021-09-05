package main

// #cgo pkg-config: libcryptsetup
// #include <errno.h>
// #include <stdlib.h>
// #include <libcryptsetup.h>
// void setuplogcb();
import "C"
import (
	"flag"
	"fmt"
)

var device = flag.String("d", "", "crypt device")

//export golog
func golog(level C.int, msg *C.char) {
	fmt.Printf("%v %v\n", level, C.GoString(msg))
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

	string_token := `
		{
			"type": "fido1",
			"keyslots": ["0"],
			"keyhandle":"dHFGueNcbENDzPqBKNEi9w8j2CAnw+OpiX25O+KeEwMOlh8kBblDKF3pcT9tcCwy0+ERjKeomrgELxTSri69wA==",
			"keyhash":"ieXEqwCI90vLwdis/W0vcgvW8M+6e05Az2bNcneitaBFNi7lDWLXe0XgB5BudnEWOqxFcl2JvnmifQ4NCe6xeA=="
		}`
	//var keyslot C.int = C.CRYPT_ANY_SLOT
	token := C.crypt_token_json_set(cd, C.CRYPT_ANY_TOKEN, C.CString(string_token))
	if token < 0 {
		fmt.Printf("crypt_token_json_set: ret %v\n", token)
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
