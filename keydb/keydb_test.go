package keydb

import "testing"

var src = "g+wZ3r/Owj/lfSwYSOSHISKNqblwOQ+2hFBFa5xAuowq+gGZVRQ42OiL01CuiPxPUlCh8+hkJqL9ChgjCRkUng== Iez6sHVqePFcSNCmpL1LIzxPzxXERhDW+FKzb1jkFv/9HWhDBgURucWHEtb/XM5rKTsRgepCdN3egcUKRCwxTw=="

func TestSerialization(t *testing.T) {
	ak, err := DecodeString(src)
	if err != nil {
		t.Error(err)
	}
	if ak.String() != src {
		t.Errorf("Did not serialise back to orignal form")
	}
}

func TestEncryption(t *testing.T) {
	ak, err := DecodeString(src)
	if err != nil {
		t.Error(err)
	}
	ek, err := ak.Encrypt("sample")
	if err != nil {
		t.Error(err)
	}
	if ek.String() == ak.String() {
		t.Error("Encrypted key didnt mutate")
	}
	dk, err := ek.Decrypt("sample")
	if err != nil {
		t.Error(err)
	}
	if dk.String() != ak.String() {
		t.Error("Encrypted key didnt match decrypted key")
	}
}

func TestLoadKeys(t *testing.T) {
	keys, err := LoadKeyfile("testdata/keyfile")
	if err != nil {
		t.Error(err)
	}
	if len(keys) != 2 {
		t.Errorf("Loadkeys (got: %v, want: %v)", len(keys), 2)
	}
}
