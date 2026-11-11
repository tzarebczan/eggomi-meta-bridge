// Package seal opens the sealed blobs the keeper forwards to the bridge
// (PROTOCOL.md section 7: login.cookies, login.secret). The construction is
// the Eggomi keeper's seal (its seal.mjs), with this bridge in the
// recipient role:
//
//	key = HKDF-SHA256(X25519(e, B) ‖ X25519(s, B), salt = grant_ref, info = "eggomi/cah-seal/v1")
//	ct  = AES-256-GCM(key, iv, aad = the bound fields, the plaintext)
//
// e is a fresh ephemeral key, B the bridge's static link key, s the sealer's
// pinned static key (the guard). The static-static term means only the
// pinned sealer could have made the blob; the ephemeral term keeps each seal
// fresh. The associated data must be exactly the canonical JSON of the bound
// fields in seal.mjs's order. The plaintext (cookies, a PIN) is never logged
// and never returned in an error.
package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Version is the seal format version.
const Version = 1

const info = "eggomi/cah-seal/v1"

// BoundFields is seal.mjs's BOUND_FIELDS: the associated data's fields, in
// order. A blob whose AAD is not exactly these, canonically encoded, is
// refused.
var BoundFields = []string{
	"grant_ref",
	"nonce",
	"tenant",
	"audience",
	"recipient_instance",
	"recipient_generation",
	"origin",
	"field",
	"frame_id",
	"navigation_generation",
	"lease_fence",
	"keeper_epoch",
	"challenge",
	"requester",
	"task",
	"operation",
	"resource",
}

// Blob is the sealed envelope as it arrives in a link frame.
type Blob struct {
	V   int    `json:"v"`
	EPK string `json:"epk"` // ephemeral public key, hex
	IV  string `json:"iv"`  // AES-GCM nonce, hex
	AAD string `json:"aad"` // bound fields, canonical JSON
	CT  string `json:"ct"`  // ciphertext, hex
}

// Error carries a stable code; never the plaintext or keys.
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

var (
	// ErrPayload: malformed blob or bound fields (seal.mjs denied_payload).
	ErrPayload = &Error{Code: "denied_payload"}
	// ErrSeal: the blob does not open with these keys (seal.mjs denied_seal).
	ErrSeal = &Error{Code: "denied_seal"}
)

// Bound is the parsed associated data. Numbers stay json.Number.
type Bound map[string]any

// Str returns a bound field as a string ("" when absent or not a string).
func (b Bound) Str(name string) string {
	s, _ := b[name].(string)
	return s
}

func isHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// canonicalBound parses aad and checks it is exactly seal.mjs's boundBytes:
// JSON.stringify of an object holding every bound field, in order, non-null,
// nothing else.
func canonicalBound(aad string) (Bound, bool) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(aad))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil || raw == nil || dec.More() {
		return nil, false
	}
	if len(raw) != len(BoundFields) {
		return nil, false
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, name := range BoundFields {
		v, ok := raw[name]
		if !ok || string(v) == "null" {
			return nil, false
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		k, _ := json.Marshal(name)
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	if buf.String() != aad {
		return nil, false
	}
	bound := Bound{}
	dec = json.NewDecoder(strings.NewReader(aad))
	dec.UseNumber()
	if err := dec.Decode(&bound); err != nil {
		return nil, false
	}
	return bound, true
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Open decrypts the blob with the bridge's static private key and the pinned
// sealer public key, and returns the plaintext and the bound fields for the
// caller's own checks. The caller must zero the plaintext when done.
func Open(bridgePrivate, sealerPublic []byte, blob *Blob) ([]byte, Bound, error) {
	if blob == nil || blob.V != Version || !isHex(blob.EPK) || !isHex(blob.IV) || !isHex(blob.CT) {
		return nil, nil, ErrPayload
	}
	bound, ok := canonicalBound(blob.AAD)
	if !ok {
		return nil, nil, ErrPayload
	}
	grantRef := bound.Str("grant_ref")
	if !isHex(grantRef) {
		return nil, nil, ErrPayload
	}

	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(bridgePrivate)
	if err != nil {
		return nil, nil, ErrPayload
	}
	epkBytes, _ := hex.DecodeString(blob.EPK)
	epk, err := curve.NewPublicKey(epkBytes)
	if err != nil {
		return nil, nil, ErrPayload
	}
	spk, err := curve.NewPublicKey(sealerPublic)
	if err != nil {
		return nil, nil, ErrPayload
	}
	dh1, err := priv.ECDH(epk) // X25519(b, E) == X25519(e, B)
	if err != nil {
		return nil, nil, ErrSeal
	}
	defer zero(dh1)
	dh2, err := priv.ECDH(spk) // X25519(b, S) == X25519(s, B)
	if err != nil {
		return nil, nil, ErrSeal
	}
	defer zero(dh2)
	ikm := append(append(make([]byte, 0, 64), dh1...), dh2...)
	defer zero(ikm)
	salt, _ := hex.DecodeString(grantRef)
	key, err := hkdf.Key(sha256.New, ikm, salt, info, 32)
	if err != nil {
		return nil, nil, ErrSeal
	}
	defer zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrSeal
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrSeal
	}
	iv, _ := hex.DecodeString(blob.IV)
	if len(iv) != gcm.NonceSize() {
		return nil, nil, ErrPayload
	}
	ct, _ := hex.DecodeString(blob.CT)
	plaintext, err := gcm.Open(nil, iv, ct, []byte(blob.AAD))
	if err != nil {
		return nil, nil, ErrSeal
	}
	return plaintext, bound, nil
}

// CookieNames are the four cookies the Meta handoff carries (PROTOCOL.md section 7.1).
var CookieNames = []string{"datr", "c_user", "sb", "xs"}

// requiredCookies is upstream's FBRequiredCookies.
var requiredCookies = []string{"datr", "c_user", "xs"}

// Cookies parses a login.cookies plaintext: a JSON object of exactly the
// named cookies, with datr, c_user and xs non-empty. It returns the
// credentials map for MetaConnector.CreateUserLoginFromCredentials.
func Cookies(plaintext []byte) (map[string]any, error) {
	var payload map[string]string
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, ErrPayload
	}
	for name := range payload {
		allowed := false
		for _, n := range CookieNames {
			if name == n {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, ErrPayload
		}
	}
	for _, name := range requiredCookies {
		if payload[name] == "" {
			return nil, ErrPayload
		}
	}
	creds := make(map[string]any, len(payload))
	for name, value := range payload {
		if value != "" {
			creds[name] = value
		}
	}
	return creds, nil
}
