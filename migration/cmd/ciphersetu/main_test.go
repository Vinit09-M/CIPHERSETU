package main

import (
	"ciphersetu/internal/envelope"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIWorkflow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	var out bytes.Buffer
	if e := run([]string{"demo", "--dir", dir}, &out); e != nil {
		t.Fatal(e)
	}
	p := func(s string) string { return filepath.Join(dir, s) }
	for _, args := range [][]string{{"inspect", "--in", p("migrated.aegis")}, {"verify", "--in", p("migrated.aegis"), "--private", p("hybrid-keys/private.json"), "--original", p("sample.txt")}, {"decrypt", "--in", p("migrated.aegis"), "--private", p("hybrid-keys/private.json"), "--out", p("second.txt")}, {"encrypt", "--in", p("sample.txt"), "--public", p("hybrid-keys/public.json"), "--out", p("fresh.aegis")}} {
		if e := run(args, &out); e != nil {
			t.Fatal(args, e)
		}
	}
	bad := [][]string{{"demo", "--dir", dir}, {"encrypt", "--in", p("sample.txt"), "--public", p("legacy-keys/public.json"), "--out", p("should-not-exist")}, {"decrypt", "--in", p("migrated.aegis"), "--private", p("legacy-keys/private.json"), "--out", p("should-not-exist")}, {"migrate", "--in", p("legacy.aegis"), "--old-private", p("legacy-keys/private.json"), "--new-private", p("hybrid-keys/private.json"), "--out", p("legacy.aegis")}, {"verify", "--in", p("migrated.aegis"), "--private", p("hybrid-keys/private.json"), "--original", p("legacy.aegis")}, {"inspect", "--in", p("migrated.aegis"), "--private", "ignored"}}
	for _, args := range bad {
		if e := run(args, &out); e == nil {
			t.Fatal("accepted", args)
		}
	}
	if _, e := os.Stat(p("should-not-exist")); !os.IsNotExist(e) {
		t.Fatal("failure published output")
	}
	v, e := envelope.Load(p("legacy.aegis"))
	if e != nil || v.Suite != envelope.Legacy {
		t.Fatal("source changed")
	}
}
