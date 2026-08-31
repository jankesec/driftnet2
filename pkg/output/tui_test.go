package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jankesec/driftnet2/pkg/protocol"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestPrintCredentialPassword(t *testing.T) {
	ui := NewTerminalUI("eth0", "AF_PACKET")
	c := protocol.Credential{
		Protocol: "ftp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 21,
		Username: "bob", Password: "secret",
	}
	out := captureStdout(t, func() { ui.PrintCredential(c) })
	if !strings.Contains(out, "bob") || !strings.Contains(out, "secret") {
		t.Errorf("output missing creds: %q", out)
	}
	if !strings.Contains(out, "→") {
		t.Errorf("output missing arrow: %q", out)
	}
}
