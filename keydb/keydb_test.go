package keydb

import "testing"

var src = "406d4db369985ee0d639f8b441f471f987c51a48674e002b431e3be509266c0bc2d720586907042aba2a45074d7afa098514a58b9cd05fc5aa0268d0c8af57a6 37c58c5aaafd6a5cadf69370b86ce9004c089e0dcb29107c14f48df1ca6c375f"

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
