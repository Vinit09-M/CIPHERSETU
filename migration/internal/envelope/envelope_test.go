package envelope

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func mustKeys(t *testing.T, s string) (Key, Key) {
	t.Helper()
	a, b, e := Generate(s)
	if e != nil {
		t.Fatal(e)
	}
	return a, b
}
func TestMigration(t *testing.T) {
	old, pub := mustKeys(t, Legacy)
	next, _ := mustKeys(t, PQ)
	for _, p := range [][]byte{nil, []byte("confidential synthetic content"), bytes.Repeat([]byte{0, 255, 42}, 10000)} {
		v, e := Encrypt(p, pub)
		if e != nil {
			t.Fatal(e)
		}
		before := encoded(v)
		m, e := Migrate(v, old, next)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(before, encoded(v)) {
			t.Fatal("source mutated")
		}
		if !bytes.Equal(v.Ciphertext, m.Ciphertext) {
			t.Fatal("ciphertext changed")
		}
		got, e := Decrypt(m, next)
		if e != nil || !bytes.Equal(got, p) {
			t.Fatalf("recovery: %v", e)
		}
		if _, e = Decrypt(m, old); e == nil {
			t.Fatal("legacy key accepted")
		}
		if _, e = Migrate(m, next, next); e == nil {
			t.Fatal("remigration accepted")
		}
	}
}
func TestTamperAndWrongKeys(t *testing.T) {
	k, p := mustKeys(t, PQ)
	wrong, _ := mustKeys(t, PQ)
	v, e := Encrypt([]byte("payload"), p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decrypt(v, wrong); e == nil {
		t.Fatal("wrong private key accepted")
	}
	if _, e = Decrypt(v, p); e == nil {
		t.Fatal("public key accepted")
	}
	tests := map[string]func(*Envelope){
		"payload": func(x *Envelope) { x.Ciphertext[0] ^= 1 }, "nonce": func(x *Envelope) { x.Nonce[0] ^= 1 }, "id": func(x *Envelope) { x.Header.ID[0] ^= 1 }, "wrapped": func(x *Envelope) { x.WrappedKey[len(x.WrappedKey)-1] ^= 1 }, "encapsulation": func(x *Envelope) { x.WrappedKey[0] ^= 1 }, "recipient": func(x *Envelope) { x.Recipient = "0000000000000000000000000000000000000000000000000000000000000000" }, "version": func(x *Envelope) { x.Header.Version = 2 }, "suite": func(x *Envelope) { x.Suite = Legacy }, "shortnonce": func(x *Envelope) { x.Nonce = nil }, "cipher": func(x *Envelope) { x.Header.Cipher = "AES-128-GCM" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var c Envelope
			if e := json.Unmarshal(encoded(v), &c); e != nil {
				t.Fatal(e)
			}
			mutate(&c)
			if _, e := Decrypt(c, k); e == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
}
func TestLegacyTamperMigration(t *testing.T) {
	a, b := mustKeys(t, Legacy)
	dest, _ := mustKeys(t, PQ)
	v, e := Encrypt([]byte("test"), b)
	if e != nil {
		t.Fatal(e)
	}
	v.Ciphertext[0] ^= 1
	if _, e = Migrate(v, a, dest); e == nil {
		t.Fatal("tampered source migrated")
	}
}
func TestFreshEncryption(t *testing.T) {
	k, p := mustKeys(t, PQ)
	a, _ := Encrypt([]byte("same"), p)
	b, _ := Encrypt([]byte("same"), p)
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedKey, b.WrappedKey) || bytes.Equal(a.Header.ID, b.Header.ID) {
		t.Fatal("randomized encryption repeated")
	}
	if _, e := Decrypt(a, k); e != nil {
		t.Fatal(e)
	}
}
func TestStrictJSON(t *testing.T) {
	for _, b := range []string{`{"version":1,"version":2}`, `{"version":1,"Version":2}`, `{"unknown":3}`, `{} {}`, `{"version":1}garbage`, `{"material":`, `null true`} {
		var k Key
		if Parse([]byte(b), &k) == nil {
			t.Fatalf("accepted %s", b)
		}
	}
}
func TestLimitsAndSave(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "file")
	if e := Save(p, []byte("original")); e != nil {
		t.Fatal(e)
	}
	if e := Save(p, []byte("overwrite")); e == nil {
		t.Fatal("overwritten")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "original" {
		t.Fatal("changed")
	}
	if _, e := Read(p, 2); e == nil {
		t.Fatal("oversize accepted")
	}
	if e := Save(filepath.Join(d, "absent", "file"), nil); e == nil {
		t.Fatal("missing parent accepted")
	}
	if _, e := Encrypt(make([]byte, MaxPlain+1), Key{}); e == nil {
		t.Fatal("oversize plaintext accepted")
	}
	files, _ := os.ReadDir(d)
	if len(files) != 1 {
		t.Fatal("temporary file leaked")
	}
}
func TestKeySerialization(t *testing.T) {
	for _, s := range []string{Legacy, PQ} {
		a, b := mustKeys(t, s)
		dir := t.TempDir()
		p := filepath.Join(dir, "key.json")
		if e := SaveJSON(p, a); e != nil {
			t.Fatal(e)
		}
		loaded, e := LoadKey(p)
		if e != nil {
			t.Fatal(e)
		}
		x, _ := loaded.ID()
		y, _ := b.ID()
		if x != y {
			t.Fatal("key identity mismatch")
		}
	}
}
func FuzzParseEnvelope(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"header":{"format":"CipherSetu"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var v Envelope
		if Parse(b, &v) == nil {
			_ = v.Validate()
		}
	})
}
