package u2fapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

// ECPublicKey is an uncompressed ECDSA public key
type ECPublicKey [65]byte

// FacetID is aka ApplicationID
type FacetID [32]byte

type Client struct {
	FacetID FacetID
}

// NewClient will Generate a new Client from a given facet url
func NewClient(url string) Client {
	return Client{FacetID: sha256.Sum256([]byte(url))}
}

type KeyHandle []byte

type KeyHandler interface {
	KeyHandle() KeyHandle
}

type SignedKeyHandle struct {
	kh        KeyHandle
	PublicKey ECPublicKey
}

func (skh SignedKeyHandle) KeyHandle() KeyHandle {
	return skh.kh
}

type RegisterResponse struct {
	PublicKey       ECPublicKey
	KeyHandle       KeyHandle
	AttestationCert []byte
	Signature       []byte
}

func (r RegisterResponse) SignedKeyHandle() SignedKeyHandle {
	return SignedKeyHandle{kh: r.KeyHandle, PublicKey: r.PublicKey}
}

type AuthenticateResponse struct {
	u2ftoken.AuthenticateResponse
	KeyHandle
	KeyHandleIndex      int
	AuthenticateRequest u2ftoken.AuthenticateRequest
}

type Winker interface {
	Wink() error
}

// ecdsa der signatures are 70,71,72 bytes, try each in turn to parse a signature
func findSignatureOffset(data []byte) (int, error) {
	sig := struct {
		R *big.Int
		S *big.Int
	}{}

	offset := len(data) - 72

	for i := 0; i < 3; i++ {
		_, err := asn1.Unmarshal(data[offset+i:], &sig)
		if err == nil {
			return offset + i, nil
		}
	}

	return 0, errors.New("Couldnt find signature")
}

func ParseRegisterResponse(data []byte) (*RegisterResponse, error) {
	var r RegisterResponse
	// TODO: 68 + X509 min + signature min(32?)
	if len(data) < 100 {
		return nil, errors.New("RegisterResponse: Too short")
	}
	if data[0] != 0x05 {
		return nil, errors.New("RegisterResponse: Reserved byte != 0x05")
	}
	copy(r.PublicKey[:], data[1:66])
	khlen := int(data[66])
	if len(data) < 67+khlen {
		return nil, errors.New("RegisterResponse: Too short for keyhandle length")
	}
	r.KeyHandle = data[67 : 67+khlen]

	// go x509/asn1 parsing explodes on ecdsa certs, this is a horrible kludge
	sigoffset, err := findSignatureOffset(data[67+khlen:])
	if err != nil {
		return nil, errors.New("RegisterResponse: Couldnt parse signature")
	}

	r.AttestationCert = data[67+khlen : 67+khlen+sigoffset]
	r.Signature = data[67+khlen+sigoffset:]
	return &r, nil
}

type Token struct {
	*u2ftoken.Token
	Winker Winker
}

func (t *Token) Wink() error {
	return t.Winker.Wink()
}

func Tokens() []*Token {
	tokens := make([]*Token, 0)
	devices, err := u2fhid.Devices()
	if err != nil {
		log.Print(err)
		return nil
	}

	for _, d := range devices {
		dev, err := u2fhid.Open(d)
		if err != nil {
			log.Print(err)
			continue
		}
		t := u2ftoken.NewToken(dev)
		version, err := t.Version()
		if err != nil {
			log.Println(err)
		} else if version == "U2F_V2" {
			tokens = append(tokens, &Token{Token: t, Winker: dev})
		}
	}
	return tokens
}

func getChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, challenge)
	if err != nil {
		return nil, err
	}
	if n != 32 {
		return nil, errors.New("Could not read enough random data")
	}
	return challenge, nil
}

func (u Client) Register(ctx context.Context) (*RegisterResponse, error) {
	u2fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	challenge, err := getChallenge()
	if err != nil {
		return nil, err
	}

	req := u2ftoken.RegisterRequest{Challenge: challenge, Application: u.FacetID[:]}

	c := make(chan RegisterResponse, 1)
	for {
		go func() {
			for _, t := range Tokens() {
				res, err := t.Register(req)
				if err == u2ftoken.ErrPresenceRequired {
					t.Wink()
				} else if err != nil {
					log.Print(err)
				} else {
					resp, err := ParseRegisterResponse(res)
					if err != nil {
						log.Print(err)
					} else {
						c <- *resp
					}
				}
			}
		}()
		select {
		case <-u2fctx.Done():
			return nil, nil // Context Closed error?
		case res := <-c:
			return &res, nil
		case <-time.After(200 * time.Millisecond):
			continue
		}
	}

}

func (u Client) Authenticate(ctx context.Context, keyhandlers []KeyHandler) (*AuthenticateResponse, error) {
	u2fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	challenge, err := getChallenge()
	if err != nil {
		return nil, err
	}
	c := make(chan AuthenticateResponse, 1)
	for {
		go func() {
			for i := range keyhandlers {
				req := u2ftoken.AuthenticateRequest{
					Challenge:   challenge,
					Application: u.FacetID[:],
					KeyHandle:   keyhandlers[i].KeyHandle(),
				}
				for _, t := range Tokens() {
					res, err := t.Authenticate(req)
					if err == u2ftoken.ErrUnknownKeyHandle {
						// TODO: dont ask device again whilst attached
						continue
					} else if err == u2ftoken.ErrPresenceRequired {
						t.Wink()
					} else if err != nil {
						log.Print(err)
					} else {
						c <- AuthenticateResponse{
							AuthenticateRequest:  req,
							AuthenticateResponse: *res,
							KeyHandle:            keyhandlers[i].KeyHandle(),
							KeyHandleIndex:       i,
						}
					}
				}
			}
		}()
		select {
		case <-u2fctx.Done():
			return nil, nil // Context Closed error?
		case res := <-c:
			return &res, nil
		case <-time.After(200 * time.Millisecond):
			continue
		}
	}

}
