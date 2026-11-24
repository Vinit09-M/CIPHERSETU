package main

import (
	"ciphersetu/internal/envelope"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const version = "0.1.0-alpha"
const help = `CipherSetu — Move encrypted data toward quantum resilience.
Research alpha. Only CipherSetu v1 files; maximum plaintext 16 MiB.

Commands:
  demo       --dir demo-output
  keygen     --type hybrid|rsa-demo --dir NEW_DIRECTORY
  encrypt    --in FILE --public KEY --out ENVELOPE [--legacy-demo]
  inspect    --in ENVELOPE
  migrate    --in ENVELOPE --old-private KEY --new-private KEY --out NEW_ENVELOPE
  verify     --in ENVELOPE --private KEY [--original FILE]
  decrypt    --in ENVELOPE --private KEY --out FILE
  version

All writes refuse existing destinations. Migration verifies recovery before publishing.
Private keys are unencrypted local files: use only synthetic data for this alpha.
JSON reports go to stdout; errors go to stderr with a nonzero exit code.
`

func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "CipherSetu:", e)
		os.Exit(1)
	}
}
func report(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func run(args []string, w io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		_, e := fmt.Fprint(w, help)
		return e
	}
	if args[0] == "version" {
		return report(w, map[string]string{"name": "CipherSetu", "version": version})
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	// Flags are deliberately registered per command; inappropriate flags cannot be silently ignored.
	var in, out, key, old, newKey, pub, dir, kind, original string
	var legacy bool
	switch args[0] {
	case "demo":
		fs.StringVar(&dir, "dir", "demo-output", "new demo directory")
	case "keygen":
		fs.StringVar(&dir, "dir", "", "new key directory")
		fs.StringVar(&kind, "type", "hybrid", "hybrid or rsa-demo")
	case "encrypt":
		fs.StringVar(&in, "in", "", "input")
		fs.StringVar(&out, "out", "", "output")
		fs.StringVar(&pub, "public", "", "public key")
		fs.BoolVar(&legacy, "legacy-demo", false, "allow demo RSA")
	case "migrate":
		fs.StringVar(&in, "in", "", "input")
		fs.StringVar(&out, "out", "", "output")
		fs.StringVar(&old, "old-private", "", "source private key")
		fs.StringVar(&newKey, "new-private", "", "destination private key")
	case "inspect":
		fs.StringVar(&in, "in", "", "input")
	case "verify":
		fs.StringVar(&in, "in", "", "input")
		fs.StringVar(&key, "private", "", "private key")
		fs.StringVar(&original, "original", "", "optional original")
	case "decrypt":
		fs.StringVar(&in, "in", "", "input")
		fs.StringVar(&out, "out", "", "output")
		fs.StringVar(&key, "private", "", "private key")
	default:
		return errors.New("unknown command; run ciphersetu help")
	}
	if e := fs.Parse(args[1:]); e != nil {
		return fmt.Errorf("%w; run ciphersetu help", e)
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	switch args[0] {
	case "demo":
		if dir == "" {
			return errors.New("--dir required")
		}
		return demo(dir, w)
	case "keygen":
		if dir == "" {
			return errors.New("--dir required")
		}
		suite := envelope.PQ
		if kind == "rsa-demo" {
			suite = envelope.Legacy
		} else if kind != "hybrid" {
			return errors.New("invalid key type")
		}
		if e := keygen(dir, suite); e != nil {
			return e
		}
		return report(w, map[string]any{"status": "created", "directory": dir, "suite": suite, "private_key_storage": "unencrypted; local research use only"})
	case "encrypt":
		if in == "" || out == "" || pub == "" {
			return errors.New("--in, --public and --out required")
		}
		k, e := envelope.LoadKey(pub)
		if e != nil {
			return e
		}
		if k.Kind != "public" {
			return errors.New("public key file required")
		}
		if k.Suite == envelope.Legacy && !legacy {
			return errors.New("RSA encryption requires --legacy-demo; use hybrid for new files")
		}
		p, e := envelope.Read(in, envelope.MaxPlain)
		if e != nil {
			return e
		}
		defer clear(p)
		v, e := envelope.Encrypt(p, k)
		if e != nil {
			return e
		}
		if e = envelope.SaveJSON(out, v); e != nil {
			return e
		}
		return report(w, map[string]any{"status": "encrypted", "suite": v.Suite, "output": out})
	}
	if in == "" {
		return errors.New("--in required")
	}
	v, e := envelope.Load(in)
	if e != nil {
		return e
	}
	switch args[0] {
	case "inspect":
		return report(w, envelope.Summary(v))
	case "migrate":
		if old == "" || newKey == "" || out == "" {
			return errors.New("--old-private, --new-private and --out required")
		}
		a, e := envelope.LoadKey(old)
		if e != nil {
			return e
		}
		b, e := envelope.LoadKey(newKey)
		if e != nil {
			return e
		}
		m, e := envelope.Migrate(v, a, b)
		if e != nil {
			return e
		}
		if e = envelope.SaveJSON(out, m); e != nil {
			return e
		}
		return report(w, map[string]any{"status": "migrated", "verified": true, "source_suite": v.Suite, "destination_suite": m.Suite, "ciphertext_preserved": bytes.Equal(v.Ciphertext, m.Ciphertext), "original_preserved": true, "output": out, "time_utc": time.Now().UTC().Format(time.RFC3339), "warning": "Previously collected legacy copies remain exposed. Data key was rewrapped, not rotated."})
	case "decrypt", "verify":
		if key == "" {
			return errors.New("--private required")
		}
		if args[0] == "decrypt" && out == "" {
			return errors.New("--out required")
		}
		k, e := envelope.LoadKey(key)
		if e != nil {
			return e
		}
		p, e := envelope.Decrypt(v, k)
		if e != nil {
			return e
		}
		defer clear(p)
		if args[0] == "decrypt" {
			if e = envelope.Save(out, p); e != nil {
				return e
			}
			return report(w, map[string]any{"status": "decrypted", "output": out})
		}
		if original != "" {
			b, e := envelope.Read(original, envelope.MaxPlain)
			if e != nil {
				return e
			}
			defer clear(b)
			if !bytes.Equal(p, b) {
				return errors.New("original content does not match")
			}
		}
		return report(w, map[string]any{"status": "verified", "authenticated": true, "original_compared": original != "", "suite": v.Suite, "bytes": len(p)})
	}
	return errors.New("unreachable command")
}
func keygen(dir, suite string) error {
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	a, b, e := envelope.Generate(suite)
	if e != nil {
		return e
	}
	if e = envelope.SaveJSON(filepath.Join(dir, "private.json"), a); e != nil {
		return e
	}
	return envelope.SaveJSON(filepath.Join(dir, "public.json"), b)
}
func demo(dir string, w io.Writer) error {
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	p := func(parts ...string) string { return filepath.Join(append([]string{dir}, parts...)...) }
	if e := keygen(p("legacy-keys"), envelope.Legacy); e != nil {
		return e
	}
	if e := keygen(p("hybrid-keys"), envelope.PQ); e != nil {
		return e
	}
	sample := []byte("CipherSetu synthetic customer document. No real personal data.\n")
	if e := envelope.Save(p("sample.txt"), sample); e != nil {
		return e
	}
	old, e := envelope.LoadKey(p("legacy-keys", "private.json"))
	if e != nil {
		return e
	}
	dest, e := envelope.LoadKey(p("hybrid-keys", "private.json"))
	if e != nil {
		return e
	}
	legacy, e := envelope.Encrypt(sample, old)
	if e != nil {
		return e
	}
	if e = envelope.SaveJSON(p("legacy.aegis"), legacy); e != nil {
		return e
	}
	migrated, e := envelope.Migrate(legacy, old, dest)
	if e != nil {
		return e
	}
	if e = envelope.SaveJSON(p("migrated.aegis"), migrated); e != nil {
		return e
	}
	recovered, e := envelope.Decrypt(migrated, dest)
	if e != nil {
		return e
	}
	if !bytes.Equal(sample, recovered) {
		return errors.New("demo recovery mismatch")
	}
	if e = envelope.Save(p("recovered.txt"), recovered); e != nil {
		return e
	}
	_, e = envelope.Decrypt(migrated, old)
	if e == nil {
		return errors.New("old key unexpectedly accepted")
	}
	tampered := migrated
	tampered.Ciphertext = bytes.Clone(migrated.Ciphertext)
	tampered.Ciphertext[0] ^= 1
	_, e = envelope.Decrypt(tampered, dest)
	if e == nil {
		return errors.New("tampered file unexpectedly accepted")
	}
	r := map[string]any{"project": "CipherSetu", "version": version, "status": "PASS", "migration_verified": true, "ciphertext_preserved": bytes.Equal(legacy.Ciphertext, migrated.Ciphertext), "old_key_rejected_for_new_envelope": true, "tampered_copy_rejected": true, "source_suite": envelope.Legacy, "destination_suite": envelope.PQ, "warning": "Research alpha. Old encrypted copies remain vulnerable; local private keys are unencrypted."}
	if e = envelope.SaveJSON(p("report.json"), r); e != nil {
		return e
	}
	return report(w, r)
}
