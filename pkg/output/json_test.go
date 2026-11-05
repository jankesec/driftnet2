package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jankesec/driftnet2/internal/buildinfo"
	"github.com/jankesec/driftnet2/pkg/protocol"
)

func TestWriteJSONRoundTrip(t *testing.T) {
	creds := []protocol.Credential{{
		Protocol: "ftp", Type: "login",
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 21,
		Username: "u", Password: "p",
		Timestamp: time.Unix(0, 0).UTC(),
	}}
	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteJSON(creds, path); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Metadata struct {
			Tool    string `json:"tool"`
			Version string `json:"version"`
			Count   int    `json:"count"`
		} `json:"metadata"`
		Credentials []protocol.Credential `json:"credentials"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Metadata.Tool != "driftnet2" {
		t.Errorf("tool = %q, want driftnet2", decoded.Metadata.Tool)
	}
	if decoded.Metadata.Version != buildinfo.Version {
		t.Errorf("version = %q, want %q", decoded.Metadata.Version, buildinfo.Version)
	}
	if decoded.Metadata.Count != 1 {
		t.Errorf("count = %d, want 1", decoded.Metadata.Count)
	}
	if len(decoded.Credentials) != 1 || decoded.Credentials[0].Password != "p" {
		t.Errorf("credentials round-trip mismatch: %+v", decoded.Credentials)
	}
}

func TestWriteJSONAtomicallyReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(nil, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms = %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("replacement is not valid JSON: %q", data)
	}
}

func TestWriteJSONPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteJSON(nil, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms = %v, want 0600", info.Mode().Perm())
	}
}
