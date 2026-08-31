package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBPFObjectFlag(t *testing.T) {
	dir := t.TempDir()
	obj := filepath.Join(dir, "custom.o")
	if err := os.WriteFile(obj, []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := resolveBPFObject(obj)
	if !ok || got != obj {
		t.Fatalf("flag path: got (%q,%v), want (%q,true)", got, ok, obj)
	}
}

func TestResolveBPFObjectEnv(t *testing.T) {
	dir := t.TempDir()
	obj := filepath.Join(dir, "xdp_sniff.o")
	if err := os.WriteFile(obj, []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DRIFTNET2_BPF", obj)
	got, ok := resolveBPFObject("")
	if !ok || got != obj {
		t.Fatalf("env path: got (%q,%v), want (%q,true)", got, ok, obj)
	}
}

func TestResolveBPFObjectFlagBeatsEnv(t *testing.T) {
	dir := t.TempDir()
	flagObj := filepath.Join(dir, "flag.o")
	envObj := filepath.Join(dir, "env.o")
	for _, p := range []string{flagObj, envObj} {
		if err := os.WriteFile(p, []byte{0}, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DRIFTNET2_BPF", envObj)
	got, ok := resolveBPFObject(flagObj)
	if !ok || got != flagObj {
		t.Fatalf("precedence: got (%q,%v), want (%q,true)", got, ok, flagObj)
	}
}

func TestResolveBPFObjectMissing(t *testing.T) {
	t.Setenv("DRIFTNET2_BPF", "")
	if got, ok := resolveBPFObject(filepath.Join(t.TempDir(), "nope.o")); ok {
		t.Fatalf("missing object should not resolve, got %q", got)
	}
}

func TestParseProtoSetSubset(t *testing.T) {
	got := parseProtoSet("http,dns,smb")
	for _, p := range []string{"http", "dns", "smb"} {
		if !got[p] {
			t.Errorf("expected %q in set", p)
		}
	}
	if got["ftp"] {
		t.Errorf("did not expect ftp in set")
	}
}

func TestParseProtoSetTrimAndLower(t *testing.T) {
	got := parseProtoSet(" HTTP , DnS ")
	if !got["http"] || !got["dns"] {
		t.Errorf("expected normalized http/dns, got %v", got)
	}
}
