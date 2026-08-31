package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jankesec/driftnet2/pkg/protocol"
)

func findByProtocol(r *Report, proto string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Protocol == proto {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestAnalyzeSeverityMapping(t *testing.T) {
	creds := []protocol.Credential{
		{Protocol: "FTP", Type: "Login", SrcIP: "192.0.2.10", DstIP: "198.51.100.20", Username: "demo", Password: "p"},
		{Protocol: "SMB", Type: "NTLMv2", SrcIP: "192.0.2.11", DstIP: "198.51.100.21", Hash: "deadbeef"},
		{Protocol: "HTTP", Type: "Bearer Token", SrcIP: "192.0.2.12", DstIP: "198.51.100.22", Token: "tok"},
		{Protocol: "DNS", Type: "Tunnel", SrcIP: "192.0.2.13", DstIP: "198.51.100.23", DNSQuery: "a.b.c"},
	}
	r := Analyze(creds)

	if got := findByProtocol(r, "FTP"); got == nil || got.Severity != High {
		t.Errorf("FTP severity: %+v, want High", got)
	}
	if got := findByProtocol(r, "SMB"); got == nil || got.Severity != High {
		t.Errorf("SMB severity: %+v, want High", got)
	}
	if got := findByProtocol(r, "HTTP"); got == nil || got.Severity != Medium {
		t.Errorf("HTTP token severity: %+v, want Medium", got)
	}
	if got := findByProtocol(r, "DNS"); got == nil || got.Severity != Medium {
		t.Errorf("DNS severity: %+v, want Medium", got)
	}
}

func TestAnalyzeGroupingAndEndpoints(t *testing.T) {
	creds := []protocol.Credential{
		{Protocol: "FTP", Type: "Login", SrcIP: "192.0.2.10", DstIP: "198.51.100.20", Password: "p"},
		{Protocol: "FTP", Type: "Login", SrcIP: "192.0.2.10", DstIP: "198.51.100.20", Password: "p2"}, // same endpoint
		{Protocol: "FTP", Type: "Login", SrcIP: "192.0.2.99", DstIP: "198.51.100.20", Password: "p3"}, // new endpoint
	}
	r := Analyze(creds)
	ftp := findByProtocol(r, "FTP")
	if ftp == nil {
		t.Fatal("no FTP finding")
	}
	if ftp.Count != 3 {
		t.Errorf("Count = %d, want 3", ftp.Count)
	}
	if len(ftp.Endpoints) != 2 {
		t.Errorf("unique endpoints = %d (%v), want 2", len(ftp.Endpoints), ftp.Endpoints)
	}
	if ftp.Remediation == "" || !strings.Contains(strings.ToUpper(ftp.Remediation), "SFTP") {
		t.Errorf("FTP remediation should mention SFTP: %q", ftp.Remediation)
	}
}

func TestAnalyzeTotals(t *testing.T) {
	creds := []protocol.Credential{
		{Protocol: "FTP", SrcIP: "a", DstIP: "b", Password: "p"},
		{Protocol: "SMB", SrcIP: "c", DstIP: "d", Hash: "h"},
		{Protocol: "HTTP", SrcIP: "e", DstIP: "f", Token: "t"},
	}
	r := Analyze(creds)
	if r.Totals[High] != 2 {
		t.Errorf("High total = %d, want 2", r.Totals[High])
	}
	if r.Totals[Medium] != 1 {
		t.Errorf("Medium total = %d, want 1", r.Totals[Medium])
	}
}

func TestReportTextContainsKeyFields(t *testing.T) {
	r := Analyze([]protocol.Credential{
		{Protocol: "TELNET", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Password: "x"},
	})
	txt := r.Text()
	for _, want := range []string{"HIGH", "TELNET", "SSH"} {
		if !strings.Contains(strings.ToUpper(txt), want) {
			t.Errorf("Text() missing %q:\n%s", want, txt)
		}
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	r := Analyze([]protocol.Credential{
		{Protocol: "FTP", SrcIP: "a", DstIP: "b", Password: "p"},
	})
	data, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].Protocol != "FTP" {
		t.Errorf("round-trip mismatch: %+v", decoded.Findings)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(nil)
	if r == nil {
		t.Fatal("Analyze(nil) returned nil report")
	}
	if len(r.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(r.Findings))
	}
	if _, err := r.JSON(); err != nil {
		t.Errorf("JSON on empty report: %v", err)
	}
}
