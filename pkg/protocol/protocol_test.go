package protocol

import (
	"encoding/base64"
	"testing"
)

func TestParseHTTPBasicAuth(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46UGFzc3dvcmQxMjM=\r\n\r\n")
	creds := ParseHTTP(payload, "10.0.0.1", "10.0.0.2", 80)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "admin" {
		t.Errorf("username: got %q, want %q", creds[0].Username, "admin")
	}
	if creds[0].Password != "Password123" {
		t.Errorf("password: got %q, want %q", creds[0].Password, "Password123")
	}
	if creds[0].Protocol != "HTTP" {
		t.Errorf("protocol: got %q", creds[0].Protocol)
	}
}

func TestParseHTTPBearerToken(t *testing.T) {
	payload := []byte("GET /api HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0\r\n\r\n")
	creds := ParseHTTP(payload, "10.0.0.1", "10.0.0.2", 443)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Token == "" {
		t.Error("expected non-empty token")
	}
	if creds[0].Type != "Bearer Token" {
		t.Errorf("type: got %q", creds[0].Type)
	}
}

func TestParseHTTPCookie(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123; token=xyz789; foo=bar\r\n\r\n")
	creds := ParseHTTP(payload, "10.0.0.1", "10.0.0.2", 80)
	if len(creds) < 1 {
		t.Fatalf("expected at least 1 session cookie, got %d", len(creds))
	}
	found := false
	for _, c := range creds {
		if c.Type == "Session Cookie" && c.Token == "session=abc123" {
			found = true
			break
		}
	}
	if !found {
		t.Error("did not find session=abc123 cookie")
	}
}

func TestParseHTTPFormPost(t *testing.T) {
	payload := []byte("POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\n\r\nusername=jdoe&password=secret")
	creds := ParseHTTP(payload, "10.0.0.1", "10.0.0.2", 80)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "jdoe" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Password != "secret" {
		t.Errorf("password: got %q", creds[0].Password)
	}
}

func TestParseHTTPNoContentTypeShouldNotParseForm(t *testing.T) {
	payload := []byte("POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=jdoe&password=secret")
	creds := ParseHTTP(payload, "10.0.0.1", "10.0.0.2", 80)
	if len(creds) != 0 {
		t.Fatalf("expected 0 creds without proper Content-Type, got %d", len(creds))
	}
}

func TestParseHTTPDigestAuth(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nAuthorization: Digest username=\"admin\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"def456\"\r\n\r\n")
	creds := ParseHTTP(payload, "10.0.0.1", "10.0.0.2", 80)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "admin" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Hash != "def456" {
		t.Errorf("hash: got %q", creds[0].Hash)
	}
}

func TestParseFTP(t *testing.T) {
	payload := []byte("USER ftpadmin\r\nPASS s3cret!\r\n")
	creds := ParseFTP(payload, "10.0.0.1", "10.0.0.2", 21)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "ftpadmin" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Password != "s3cret!" {
		t.Errorf("password: got %q", creds[0].Password)
	}
}

func TestParsePOP3(t *testing.T) {
	payload := []byte("USER user@test.com\r\nPASS pop3pass\r\n")
	creds := ParsePOP3(payload, "10.0.0.1", "10.0.0.2", 110)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "user@test.com" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Password != "pop3pass" {
		t.Errorf("password: got %q", creds[0].Password)
	}
}

func TestParsePOP3AuthPlain(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("\x00admin\x00plainpass"))
	payload := []byte("AUTH PLAIN " + auth + "\r\n")
	creds := ParsePOP3(payload, "10.0.0.1", "10.0.0.2", 110)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "admin" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Password != "plainpass" {
		t.Errorf("password: got %q", creds[0].Password)
	}
}

func TestParseIMAPLogin(t *testing.T) {
	payload := []byte("a001 LOGIN \"user@corp.com\" \"imappass\"\r\n")
	creds := ParseIMAP(payload, "10.0.0.1", "10.0.0.2", 143)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "user@corp.com" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Password != "imappass" {
		t.Errorf("password: got %q", creds[0].Password)
	}
}

func TestParseIMAPLiteral(t *testing.T) {
	payload := []byte("a001 LOGIN {13}\r\nuser@corp.com {8}\r\nimappass\r\n")
	creds := ParseIMAP(payload, "10.0.0.1", "10.0.0.2", 143)

	for _, c := range creds {
		t.Logf("cred: %+v", c)
	}
}

func TestParseIMAPLiteralInline(t *testing.T) {
	payload := []byte("a001 LOGIN user@corp.com imappass\r\n")
	creds := ParseIMAP(payload, "10.0.0.1", "10.0.0.2", 143)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "user@corp.com" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Password != "imappass" {
		t.Errorf("password: got %q", creds[0].Password)
	}
}

func TestParseSMTPAuthLogin(t *testing.T) {
	user := base64.StdEncoding.EncodeToString([]byte("admin"))
	payload := []byte("AUTH LOGIN " + user + "\r\n")
	creds := ParseSMTP(payload, "10.0.0.1", "10.0.0.2", 587)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "admin" {
		t.Errorf("username: got %q", creds[0].Username)
	}
}

func TestParseSMTPAuthPlain(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("\x00postmaster\x00smtppass"))
	payload := []byte("AUTH PLAIN " + auth + "\r\n")
	creds := ParseSMTP(payload, "10.0.0.1", "10.0.0.2", 25)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "postmaster" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Password != "smtppass" {
		t.Errorf("password: got %q", creds[0].Password)
	}
}

func TestParseDNS(t *testing.T) {
	payload := []byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	creds := ParseDNS(payload, "10.0.0.1", "8.8.8.8", 53)
	if len(creds) != 0 {
		t.Fatalf("expected 0 tunnel alerts for normal DNS, got %d", len(creds))
	}
}

func TestParseDNSTunnel(t *testing.T) {
	payload := buildDNSQueryPayload("aGVsbG8ud29ybGQudGhpcy5pcy5hLmxvbmcudHVubmVsLm5hbWUuYzIuZXhhbXBsZS5jb20")
	creds := ParseDNS(payload, "10.0.0.1", "8.8.8.8", 53)
	if len(creds) != 1 {
		t.Fatalf("expected 1 tunnel alert, got %d", len(creds))
	}
	if creds[0].Type != "Tunnel Detection" {
		t.Errorf("type: got %q", creds[0].Type)
	}
}

func TestParseTelnet(t *testing.T) {
	payload := []byte("Login: ")
	creds := ParseTelnet(payload, "10.0.0.1", "10.0.0.2", 23)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Type != "Session" {
		t.Errorf("type: got %q", creds[0].Type)
	}
}

func TestParseLDAPSimpleBind(t *testing.T) {
	payload := buildLDAPBindRequest("cn=admin,dc=corp", "ldappass")
	creds := ParseLDAP(payload, "10.0.0.1", "10.0.0.2", 389)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "cn=admin,dc=corp" {
		t.Errorf("username: got %q", creds[0].Username)
	}
	if creds[0].Password != "ldappass" {
		t.Errorf("password: got %q", creds[0].Password)
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy("aaaaaa"); e > 0.1 {
		t.Errorf("low-entropy string: got %f, want near 0", e)
	}
	if e := shannonEntropy("abcdefghijklmnop"); e < 3.0 {
		t.Errorf("high-entropy string: got %f, want > 3.0", e)
	}
}

func TestCredentialString(t *testing.T) {
	c := Credential{Username: "admin", Password: "pass"}
	if s := c.String(); s != "admin:pass" {
		t.Errorf("String(): got %q", s)
	}

	c2 := Credential{Token: "eyJhbGciOiJIUzI1NiJ9"}
	s := c2.String()
	if len(s) < 20 {
		t.Errorf("Token String() too short: %q", s)
	}

	c3 := Credential{DNSQuery: "tunnel.c2.example.com"}
	if s := c3.String(); s != "DNS: tunnel.c2.example.com" {
		t.Errorf("DNS String(): got %q", s)
	}
}

func TestCredentialEmoji(t *testing.T) {
	tests := []struct {
		c    Credential
		want string
	}{
		{Credential{Password: "x"}, "🔑"},
		{Credential{Hash: "abc"}, "⚡"},
		{Credential{Token: "x"}, "🍪"},
		{Credential{DNSQuery: "x"}, "🕳️"},
		{Credential{}, "📎"},
	}
	for _, tt := range tests {
		if got := tt.c.Emoji(); got != tt.want {
			t.Errorf("Emoji() for %+v: got %q, want %q", tt.c, got, tt.want)
		}
	}
}

// --- helpers ---

func buildDNSQueryPayload(qname string) []byte {
	labels := splitDNSLabels(qname)
	total := 12 + len(qname) + 2 + 4
	buf := make([]byte, total)

	buf[0] = 0x00 // ID
	buf[1] = 0x01
	buf[5] = 0x01 // QDCOUNT = 1

	offset := 12
	for _, label := range labels {
		buf[offset] = byte(len(label))
		offset++
		copy(buf[offset:], label)
		offset += len(label)
	}
	buf[offset] = 0 // zero-length label
	offset++
	buf[offset] = 0x00 // QTYPE = A
	buf[offset+1] = 0x01
	buf[offset+2] = 0x00 // QCLASS = IN
	buf[offset+3] = 0x01

	return buf
}

func splitDNSLabels(qname string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(qname); i++ {
		if qname[i] == '.' {
			labels = append(labels, qname[start:i])
			start = i + 1
		}
	}
	labels = append(labels, qname[start:])
	return labels
}

func buildLDAPBindRequest(dn, password string) []byte {
	buf := []byte{
		0x30, 0x00, // SEQUENCE (length filled later)
		0x02, 0x01, 0x01, // Message ID = 1
		0x60, 0x00, // Bind request (length filled later)
		0x02, 0x01, 0x03, // Version = 3
		0x04, byte(len(dn)), // DN octet string
	}
	buf = append(buf, []byte(dn)...)
	buf = append(buf, 0x80, byte(len(password)))
	buf = append(buf, []byte(password)...)

	buf[1] = byte(len(buf) - 2)
	buf[6] = byte(len(buf) - 7)

	return buf
}
