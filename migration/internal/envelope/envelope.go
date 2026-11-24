// Package envelope implements the versioned CipherSetu research file format.
package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	Version     = 1
	MaxPlain    = 16 << 20
	MaxEnvelope = 24 << 20
	Legacy      = "RSA-3072-OAEP-SHA256"
	PQ          = "HPKE-MLKEM768-X25519-HKDFSHA256-AES256GCM"
)

type Key struct {
	Version  int    `json:"version"`
	Suite    string `json:"suite"`
	Kind     string `json:"kind"`
	Material []byte `json:"material"`
}
type Header struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	ID      []byte `json:"id"`
	Cipher  string `json:"cipher"`
}
type Envelope struct {
	Header     Header `json:"header"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	Suite      string `json:"suite"`
	Recipient  string `json:"recipient"`
	WrappedKey []byte `json:"wrapped_key"`
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func encoded(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func gcm(k []byte) (cipher.AEAD, error) {
	if len(k) != 32 {
		return nil, errors.New("invalid data key")
	}
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}

// Parse rejects duplicate fields, unknown fields, trailing values and excessive nesting.
func Parse(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting too deep")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, e = d.Token()
				if e != nil {
					return e
				}
				k, ok := t.(string)
				if !ok || seen[strings.ToLower(k)] {
					return errors.New("duplicate JSON field")
				}
				seen[strings.ToLower(k)] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid JSON")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func Read(path string, max int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if len(b) > max {
		return nil, errors.New("file exceeds size limit")
	}
	return b, e
}
func LoadKey(path string) (Key, error) {
	var k Key
	b, e := Read(path, 16384)
	if e == nil {
		e = Parse(b, &k)
	}
	if e == nil {
		_, e = k.Public()
	}
	return k, e
}
func Load(path string) (Envelope, error) {
	var v Envelope
	b, e := Read(path, MaxEnvelope)
	if e == nil {
		e = Parse(b, &v)
	}
	if e == nil {
		e = v.Validate()
	}
	return v, e
}

// Save publishes a complete, synced file using a no-overwrite hard link. No unsafe fallback.
// A crash may leave a hidden temporary file; it never intentionally replaces an existing target.
func Save(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".ciphersetu-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Link(tmp, path); e != nil {
		return fmt.Errorf("publish failed (target must be absent; filesystem must support hard links): %w", e)
	}
	return nil
}
func SaveJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return Save(path, append(b, '\n'))
}

func Generate(suite string) (Key, Key, error) {
	private := Key{Version: Version, Suite: suite, Kind: "private"}
	switch suite {
	case Legacy:
		k, e := rsa.GenerateKey(rand.Reader, 3072)
		if e != nil {
			return Key{}, Key{}, e
		}
		private.Material, e = x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			return Key{}, Key{}, e
		}
	case PQ:
		k, e := hpke.MLKEM768X25519().GenerateKey()
		if e != nil {
			return Key{}, Key{}, e
		}
		private.Material, e = k.Bytes()
		if e != nil {
			return Key{}, Key{}, e
		}
	default:
		return Key{}, Key{}, errors.New("unsupported suite")
	}
	pub, e := private.Public()
	return private, pub, e
}
func (k Key) Public() (Key, error) {
	if k.Version != Version || (k.Kind != "private" && k.Kind != "public") {
		return Key{}, errors.New("unsupported key format")
	}
	p := Key{Version: Version, Suite: k.Suite, Kind: "public"}
	switch k.Suite {
	case Legacy:
		var pub *rsa.PublicKey
		if k.Kind == "private" {
			v, e := x509.ParsePKCS8PrivateKey(k.Material)
			if e != nil {
				return p, e
			}
			r, ok := v.(*rsa.PrivateKey)
			if !ok {
				return p, errors.New("not an RSA key")
			}
			if e = r.Validate(); e != nil {
				return p, e
			}
			pub = &r.PublicKey
		} else {
			v, e := x509.ParsePKIXPublicKey(k.Material)
			if e != nil {
				return p, e
			}
			var ok bool
			pub, ok = v.(*rsa.PublicKey)
			if !ok {
				return p, errors.New("not an RSA key")
			}
		}
		if pub.N.BitLen() != 3072 || pub.E != 65537 {
			return p, errors.New("requires RSA-3072 with exponent 65537")
		}
		var e error
		p.Material, e = x509.MarshalPKIXPublicKey(pub)
		return p, e
	case PQ:
		if k.Kind == "private" {
			v, e := hpke.MLKEM768X25519().NewPrivateKey(k.Material)
			if e != nil {
				return p, e
			}
			p.Material = v.PublicKey().Bytes()
		} else {
			v, e := hpke.MLKEM768X25519().NewPublicKey(k.Material)
			if e != nil {
				return p, e
			}
			p.Material = v.Bytes()
		}
		return p, nil
	default:
		return p, errors.New("unsupported key suite")
	}
}
func (k Key) ID() (string, error) {
	p, e := k.Public()
	if e != nil {
		return "", e
	}
	return digest(encoded(p)), nil
}
func (v Envelope) Validate() error {
	if v.Header.Format != "CipherSetu" || v.Header.Version != Version || v.Header.Cipher != "AES-256-GCM" || len(v.Header.ID) != 16 {
		return errors.New("unsupported envelope header")
	}
	if len(v.Nonce) != 12 || len(v.Ciphertext) < 16 || len(v.Ciphertext) > MaxPlain+16 {
		return errors.New("invalid payload size or nonce")
	}
	b, e := hex.DecodeString(v.Recipient)
	if e != nil || len(b) != 32 {
		return errors.New("invalid recipient identifier")
	}
	switch v.Suite {
	case Legacy:
		if len(v.WrappedKey) != 384 {
			return errors.New("invalid RSA wrapped key")
		}
	case PQ:
		if len(v.WrappedKey) != 1168 {
			return errors.New("invalid HPKE wrapped key")
		}
	default:
		return errors.New("unsupported protection suite")
	}
	return nil
}
func (v Envelope) context() []byte {
	return encoded(struct {
		Domain      string
		Header      Header
		Nonce       []byte
		PayloadHash string
		Suite       string
		Recipient   string
	}{"CipherSetu/key-wrap/v1", v.Header, v.Nonce, digest(v.Ciphertext), v.Suite, v.Recipient})
}
func wrap(v *Envelope, dek []byte, k Key) error {
	p, e := k.Public()
	if e != nil {
		return e
	}
	v.Suite = p.Suite
	v.Recipient, e = p.ID()
	if e != nil {
		return e
	}
	switch p.Suite {
	case Legacy:
		r, e := x509.ParsePKIXPublicKey(p.Material)
		if e != nil {
			return e
		}
		v.WrappedKey, e = rsa.EncryptOAEP(sha256.New(), rand.Reader, r.(*rsa.PublicKey), dek, v.context())
		return e
	case PQ:
		r, e := hpke.MLKEM768X25519().NewPublicKey(p.Material)
		if e != nil {
			return e
		}
		v.WrappedKey, e = hpke.Seal(r, hpke.HKDFSHA256(), hpke.AES256GCM(), v.context(), dek)
		return e
	}
	return errors.New("unsupported suite")
}
func unwrap(v Envelope, k Key) ([]byte, error) {
	if e := v.Validate(); e != nil {
		return nil, e
	}
	if k.Kind != "private" || k.Suite != v.Suite {
		return nil, errors.New("matching private key required")
	}
	id, e := k.ID()
	if e != nil {
		return nil, e
	}
	if id != v.Recipient {
		return nil, errors.New("wrong recipient key")
	}
	var dek []byte
	switch k.Suite {
	case Legacy:
		r, err := x509.ParsePKCS8PrivateKey(k.Material)
		if err != nil {
			return nil, err
		}
		dek, e = rsa.DecryptOAEP(sha256.New(), rand.Reader, r.(*rsa.PrivateKey), v.WrappedKey, v.context())
	case PQ:
		r, err := hpke.MLKEM768X25519().NewPrivateKey(k.Material)
		if err != nil {
			return nil, err
		}
		dek, e = hpke.Open(r, hpke.HKDFSHA256(), hpke.AES256GCM(), v.context(), v.WrappedKey)
	}
	if e != nil || len(dek) != 32 {
		return nil, errors.New("key authentication failed")
	}
	return dek, nil
}
func Encrypt(plain []byte, k Key) (Envelope, error) {
	var v Envelope
	if len(plain) > MaxPlain {
		return v, errors.New("plaintext exceeds 16 MiB limit")
	}
	v.Header = Header{"CipherSetu", Version, random(16), "AES-256-GCM"}
	v.Nonce = random(12)
	dek := random(32)
	defer clear(dek)
	a, e := gcm(dek)
	if e != nil {
		return v, e
	}
	v.Ciphertext = a.Seal(nil, v.Nonce, plain, encoded(v.Header))
	e = wrap(&v, dek, k)
	return v, e
}
func decryptWith(v Envelope, dek []byte) ([]byte, error) {
	a, e := gcm(dek)
	if e != nil {
		return nil, e
	}
	p, e := a.Open(nil, v.Nonce, v.Ciphertext, encoded(v.Header))
	if e != nil {
		return nil, errors.New("payload authentication failed")
	}
	return p, nil
}
func Decrypt(v Envelope, k Key) ([]byte, error) {
	dek, e := unwrap(v, k)
	if e != nil {
		return nil, e
	}
	defer clear(dek)
	return decryptWith(v, dek)
}

// Migrate requires the destination private key so a successful operation verifies recovery.
// It rewraps the existing DEK; it does not revoke old copies or rotate that DEK.
func Migrate(v Envelope, old, destination Key) (Envelope, error) {
	if v.Suite != Legacy || old.Suite != Legacy || destination.Suite != PQ || destination.Kind != "private" {
		return Envelope{}, errors.New("migration requires RSA source and hybrid destination private keys")
	}
	dek, e := unwrap(v, old)
	if e != nil {
		return Envelope{}, e
	}
	defer clear(dek)
	before, e := decryptWith(v, dek)
	if e != nil {
		return Envelope{}, e
	}
	defer clear(before)
	out := v
	if e = wrap(&out, dek, destination); e != nil {
		return Envelope{}, e
	}
	after, e := Decrypt(out, destination)
	if e != nil {
		return Envelope{}, e
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		return Envelope{}, errors.New("recovery verification failed")
	}
	return out, nil
}
func Summary(v Envelope) map[string]any {
	return map[string]any{"format": v.Header.Format, "version": v.Header.Version, "payload_cipher": v.Header.Cipher, "key_protection": v.Suite, "recipient_id": v.Recipient, "payload_bytes": len(v.Ciphertext) - 16, "quantum_vulnerable_key_protection": v.Suite == Legacy, "authenticated": false, "note": "Inspection is structural only. Use verify with the private key for authentication."}
}
