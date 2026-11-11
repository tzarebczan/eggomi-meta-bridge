package seal

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type vectors struct {
	BoundFields []string `json:"boundFields"`
	Seal        struct {
		SealerStatic    string            `json:"sealerStatic"`
		SealerPublic    string            `json:"sealerPublic"`
		RecipientStatic string            `json:"recipientStatic"`
		RecipientPublic string            `json:"recipientPublic"`
		Blob            Blob              `json:"blob"`
		Plaintext       map[string]string `json:"plaintext"`
	} `json:"seal"`
}

func load(t *testing.T) vectors {
	t.Helper()
	data, err := os.ReadFile("../testdata/interop.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBoundFieldsMatchKeeper(t *testing.T) {
	v := load(t)
	if strings.Join(v.BoundFields, ",") != strings.Join(BoundFields, ",") {
		t.Fatalf("bound fields drifted from seal.mjs: %v", v.BoundFields)
	}
}

// TestOpensKeeperSeal: a blob made by the keeper's seal.mjs opens here.
func TestOpensKeeperSeal(t *testing.T) {
	v := load(t)
	blob := v.Seal.Blob
	pt, bound, err := Open(mustHex(t, v.Seal.RecipientStatic), mustHex(t, v.Seal.SealerPublic), &blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	creds, err := Cookies(pt)
	if err != nil {
		t.Fatalf("cookies: %v", err)
	}
	for name, want := range v.Seal.Plaintext {
		if creds[name] != want {
			t.Fatalf("cookie %s mismatch", name)
		}
	}
	if bound.Str("recipient_instance") != "meta-bridge" || bound.Str("field") != "cookies" {
		t.Fatalf("bound: %v", bound)
	}
}

func TestRefusals(t *testing.T) {
	v := load(t)
	priv := mustHex(t, v.Seal.RecipientStatic)
	sealer := mustHex(t, v.Seal.SealerPublic)
	cases := map[string]struct {
		mutate func(b *Blob)
		key    []byte
		sealer []byte
		want   error
	}{
		"wrong sealer key":   {sealer: mustHex(t, v.Seal.RecipientPublic), want: ErrSeal},
		"wrong recipient":    {key: mustHex(t, v.Seal.SealerStatic), want: ErrSeal},
		"flipped ciphertext": {mutate: func(b *Blob) { b.CT = flipHex(b.CT) }, want: ErrSeal},
		"flipped iv":         {mutate: func(b *Blob) { b.IV = flipHex(b.IV) }, want: ErrSeal},
		"changed aad field":  {mutate: func(b *Blob) { b.AAD = strings.Replace(b.AAD, `"field":"cookies"`, `"field":"cookiez"`, 1) }, want: ErrSeal},
		"non-canonical aad":  {mutate: func(b *Blob) { b.AAD = strings.Replace(b.AAD, `{"grant_ref"`, `{ "grant_ref"`, 1) }, want: ErrPayload},
		"reordered aad": {mutate: func(b *Blob) {
			var m map[string]any
			json.Unmarshal([]byte(b.AAD), &m)
			out, _ := json.Marshal(m) // Go sorts keys: not seal.mjs's order
			b.AAD = string(out)
		}, want: ErrPayload},
		"extra aad field": {mutate: func(b *Blob) { b.AAD = strings.TrimSuffix(b.AAD, "}") + `,"x":"y"}` }, want: ErrPayload},
		"null aad field":  {mutate: func(b *Blob) { b.AAD = strings.Replace(b.AAD, `"tenant":"tenant-test"`, `"tenant":null`, 1) }, want: ErrPayload},
		"wrong version":   {mutate: func(b *Blob) { b.V = 2 }, want: ErrPayload},
		"uppercase hex":   {mutate: func(b *Blob) { b.CT = strings.ToUpper(b.CT) }, want: ErrPayload},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			blob := v.Seal.Blob
			if c.mutate != nil {
				c.mutate(&blob)
			}
			k, s := priv, sealer
			if c.key != nil {
				k = c.key
			}
			if c.sealer != nil {
				s = c.sealer
			}
			_, _, err := Open(k, s, &blob)
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func TestCookiesShape(t *testing.T) {
	ok := `{"datr":"a","c_user":"1","xs":"x","sb":"s"}`
	if _, err := Cookies([]byte(ok)); err != nil {
		t.Fatalf("valid cookies refused: %v", err)
	}
	if c, err := Cookies([]byte(`{"datr":"a","c_user":"1","xs":"x"}`)); err != nil || len(c) != 3 {
		t.Fatalf("sb must be optional: %v %v", c, err)
	}
	for _, bad := range []string{
		`{"datr":"a","c_user":"1"}`,                   // xs missing
		`{"datr":"a","c_user":"1","xs":""}`,           // xs empty
		`{"datr":"a","c_user":"1","xs":"x","fr":"y"}`, // unnamed cookie
		`[1,2]`,
		`not json`,
	} {
		if _, err := Cookies([]byte(bad)); !errors.Is(err, ErrPayload) {
			t.Fatalf("%s: want denied_payload, got %v", bad, err)
		}
	}
}

// TestErrorsCarryNoSecret: a refusal's text is its code only.
func TestErrorsCarryNoSecret(t *testing.T) {
	_, err := Cookies([]byte(`{"datr":"CANARY-DATR-VALUE","c_user":"1"}`))
	if err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("error leaks input: %v", err)
	}
}

func flipHex(s string) string {
	b, _ := hex.DecodeString(s)
	b[0] ^= 1
	return hex.EncodeToString(b)
}
