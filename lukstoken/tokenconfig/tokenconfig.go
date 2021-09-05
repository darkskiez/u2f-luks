package tokenconfig

type TokenConfig struct {
	TokenType string   `json:"type"` // must be fido1
	KeySlots  []string // which slot this token decrypts
	KeyHandle string   // keyhandle that identifies token
	KeyHash   string   // hash of key this decodes
	IDHandle  string   // keyhandle for identification of token in 2FA mode
}

