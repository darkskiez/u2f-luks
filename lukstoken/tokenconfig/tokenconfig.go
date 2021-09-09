package tokenconfig

import (
	"encoding/base64"
	"fmt"

	"github.com/darkskiez/u2f-luks/keydb"
)

type TokenConfig struct {
	TokenType string   `json:"type"`      // must be u2f
	KeySlots  []string `json:"keyslots"`  // which slot this token decrypts
	KeyHandle string   `json:"keyhandle"` // keyhandle that identifies token
	KeyHash   string   `json:"keyhash"`   // hash of key this decodes
	IDHandle  string   `json:"idhandle"`  // keyhandle for identification of token in 2FA mode
}

// New returns a new TokenConfig for the supplied key
func New(ak keydb.AuthorisedKey, idk keydb.AuthorisedKey) TokenConfig {
	tc := TokenConfig{
		TokenType: "u2f",
		KeySlots:  []string{"0"},
		KeyHandle: base64.StdEncoding.EncodeToString(ak.U2FKeyHandle),
		KeyHash:   base64.StdEncoding.EncodeToString(ak.PublicKeyHash),
	}
	if len(idk.U2FKeyHandle) > 0 {
		tc.IDHandle = base64.StdEncoding.EncodeToString(idk.U2FKeyHandle)
	}
	return tc
}

func (tc TokenConfig) AuthorisedKey() (keydb.AuthorisedKey, error) {

	kh, err := base64.StdEncoding.DecodeString(tc.KeyHandle)
	if err != nil {
		return keydb.AuthorisedKey{}, err
	}
	pkh, err := base64.StdEncoding.DecodeString(tc.KeyHash)
	if err != nil {
		return keydb.AuthorisedKey{}, err
	}

	return keydb.AuthorisedKey{
		U2FKeyHandle:  kh,
		PublicKeyHash: pkh,
	}, nil
}

func (tc TokenConfig) Validate() error {
	if tc.TokenType != "u2f" {
		return fmt.Errorf("Wrong token type (not u2f): %v", tc.TokenType)
	}
	_, err := tc.AuthorisedKey()
	return err
}
