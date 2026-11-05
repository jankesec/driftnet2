package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jankesec/driftnet2/pkg/protocol"
	"github.com/jankesec/driftnet2/pkg/sniffer"
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

func TestParseProtoSetIgnoresEmptyValues(t *testing.T) {
	got := parseProtoSet("http, ,dns,")
	if len(got) != 2 || got[""] {
		t.Errorf("expected only http and dns, got %v", got)
	}
}

func TestUnknownProtocols(t *testing.T) {
	got := unknownProtocols(parseProtoSet("HTTP, bogus, custom"))
	want := []string{"bogus", "custom"}
	if len(got) != len(want) {
		t.Fatalf("unknown protocols = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unknown protocols = %v, want %v", got, want)
		}
	}
}

func TestCredentialsFromPacketPreservesCaptureTimestamp(t *testing.T) {
	capturedAt := time.Date(2026, 11, 5, 12, 34, 56, 0, time.UTC)
	pkt := &sniffer.RawPacket{
		Timestamp: capturedAt,
		SrcIP:     "192.0.2.10",
		DstIP:     "198.51.100.20",
		DstPort:   21,
		Payload:   []byte("USER demo\r\nPASS secret\r\n"),
	}
	creds := credentialsFromPacket(pkt, parseProtoSet("ftp"))
	if len(creds) != 1 {
		t.Fatalf("got %d credentials, want 1", len(creds))
	}
	if !creds[0].Timestamp.Equal(capturedAt) {
		t.Fatalf("timestamp = %s, want %s", creds[0].Timestamp, capturedAt)
	}
}

func TestDestination(t *testing.T) {
	tests := []struct {
		name string
		cred protocol.Credential
		want string
	}{
		{name: "IPv4", cred: protocol.Credential{DstIP: "198.51.100.20", DstPort: 443}, want: "198.51.100.20:443"},
		{name: "IPv6", cred: protocol.Credential{DstIP: "2001:db8::1", DstPort: 443}, want: "[2001:db8::1]:443"},
		{name: "no port", cred: protocol.Credential{DstIP: "198.51.100.20"}, want: "198.51.100.20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := destination(tt.cred); got != tt.want {
				t.Fatalf("destination() = %q, want %q", got, tt.want)
			}
		})
	}
}
