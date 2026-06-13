package protocol

import (
	"encoding/base64"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

type Credential struct {
	Protocol  string    `json:"protocol"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	DstPort   uint16    `json:"dst_port"`
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	Token     string    `json:"token,omitempty"`
	Hash      string    `json:"hash,omitempty"`
	Raw       string    `json:"raw,omitempty"`
	DNSQuery  string    `json:"dns_query,omitempty"`
}

func (c Credential) String() string {
	switch {
	case c.Password != "":
		return fmt.Sprintf("%s:%s", c.Username, c.Password)
	case c.Hash != "":
		return c.Hash[:min(len(c.Hash), 40)]
	case c.Token != "":
		return c.Token[:min(len(c.Token), 40)] + "..."
	case c.DNSQuery != "":
		return "DNS: " + c.DNSQuery
	default:
		return c.Raw
	}
}

func (c Credential) Emoji() string {
	switch {
	case c.Password != "":
		return "🔑"
	case c.Hash != "":
		return "⚡"
	case c.Token != "":
		return "🍪"
	case c.DNSQuery != "":
		return "🕳️"
	default:
		return "📎"
	}
}

func newCred(proto, ctype, srcIP, dstIP string, dstPort uint16) Credential {
	return Credential{
		Protocol:  proto,
		Type:      ctype,
		Timestamp: time.Now(),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		DstPort:   dstPort,
	}
}

// --- HTTP ---

func ParseHTTP(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	text := string(payload)
	var creds []Credential

	lines := strings.Split(text, "\r\n")
	headerEnd := -1
	contentType := ""

	for i, line := range lines {
		if line == "" {
			headerEnd = i
			break
		}

		if strings.HasPrefix(line, "Authorization: Basic ") {
			b64 := strings.TrimPrefix(line, "Authorization: Basic ")
			b64 = strings.TrimSpace(b64)
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					c := newCred("HTTP", "Basic Auth", srcIP, dstIP, dstPort)
					c.Username = parts[0]
					c.Password = parts[1]
					creds = append(creds, c)
				}
			}
		}

		if strings.HasPrefix(line, "Authorization: Bearer ") {
			c := newCred("HTTP", "Bearer Token", srcIP, dstIP, dstPort)
			c.Token = strings.TrimSpace(strings.TrimPrefix(line, "Authorization: Bearer "))
			creds = append(creds, c)
		}

		if strings.HasPrefix(line, "Authorization: Digest ") {
			c := newCred("HTTP", "Digest Auth", srcIP, dstIP, dstPort)
			digestStr := strings.TrimPrefix(line, "Authorization: Digest ")
			c.Raw = digestStr
			if u := extractDigestField(digestStr, "username"); u != "" {
				c.Username = u
			}
			if r := extractDigestField(digestStr, "response"); r != "" {
				c.Hash = r
			}
			creds = append(creds, c)
		}

		if strings.HasPrefix(line, "Authorization: NTLM ") {
			b64 := strings.TrimSpace(strings.TrimPrefix(line, "Authorization: NTLM "))
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err == nil {
				ntlm := extractNTLMFields(decoded)
				if ntlm != nil {
					c := newCred("HTTP", "NTLM Auth", srcIP, dstIP, dstPort)
					if ntlm.user != "" {
						c.Username = ntlm.domain + "\\" + ntlm.user
					}
					c.Hash = fmt.Sprintf("%s::%s:%s:%s:%s",
						ntlm.user, ntlm.domain,
						ntlm.challenge, ntlm.response, ntlm.ntproof)
					creds = append(creds, c)
				}
			}
		}

		if strings.HasPrefix(strings.ToLower(line), "cookie:") {
			cookieStr := line[len("cookie:"):]
			for _, c := range strings.Split(cookieStr, ";") {
				c = strings.TrimSpace(c)
				cLower := strings.ToLower(c)
				if strings.Contains(cLower, "session") || strings.Contains(cLower, "token") ||
					strings.Contains(cLower, "auth") || strings.Contains(cLower, "sid") {
					cr := newCred("HTTP", "Session Cookie", srcIP, dstIP, dstPort)
					cr.Token = c
					creds = append(creds, cr)
				}
			}
		}

		lineLower := strings.ToLower(line)
		for _, hdr := range []struct{ prefix, name string }{
			{"x-api-key:", "X-Api-Key"},
			{"x-auth-token:", "X-Auth-Token"},
			{"authorization: token ", "Authorization Token"},
		} {
			if strings.HasPrefix(lineLower, hdr.prefix) {
				c := newCred("HTTP", hdr.name, srcIP, dstIP, dstPort)
				c.Token = strings.TrimSpace(line[len(hdr.prefix):])
				creds = append(creds, c)
			}
		}

		if strings.HasPrefix(strings.ToLower(line), "content-type:") {
			contentType = strings.TrimSpace(line[len("content-type:"):])
		}
	}

	if headerEnd >= 0 && headerEnd < len(lines)-1 && strings.Contains(strings.ToLower(contentType), "x-www-form-urlencoded") {
		body := strings.Join(lines[headerEnd+1:], "\r\n")
		parsed, err := url.ParseQuery(body)
		if err == nil {
			for userKey, userVals := range parsed {
				userKeyLower := strings.ToLower(userKey)
				if strings.Contains(userKeyLower, "user") || strings.Contains(userKeyLower, "name") ||
					strings.Contains(userKeyLower, "email") || userKeyLower == "login" {
					for pwKey, pwVals := range parsed {
						pwKeyLower := strings.ToLower(pwKey)
						if strings.Contains(pwKeyLower, "pass") || strings.Contains(pwKeyLower, "pwd") ||
							strings.Contains(pwKeyLower, "secret") || strings.Contains(pwKeyLower, "key") {
							if len(userVals) > 0 && len(pwVals) > 0 {
								c := newCred("HTTP", "POST Form", srcIP, dstIP, dstPort)
								c.Username = userVals[0]
								c.Password = pwVals[0]
								creds = append(creds, c)
							}
						}
					}
					break
				}
			}
		}
	}

	return creds
}

func extractDigestField(digest, field string) string {
	key := field + "=\""
	idx := strings.Index(strings.ToLower(digest), strings.ToLower(key))
	if idx < 0 {
		return ""
	}
	rest := digest[idx+len(key):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// --- DNS ---

func ParseDNS(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	if len(payload) < 12 {
		return nil
	}

	var labels []string
	offset := 12
	for offset < len(payload) {
		l := int(payload[offset])
		if l == 0 {
			break
		}
		if l&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset++
		if offset+l > len(payload) {
			break
		}
		labels = append(labels, string(payload[offset:offset+l]))
		offset += l
	}

	if len(labels) == 0 {
		return nil
	}

	qname := strings.Join(labels, ".")

	if isSuspiciousDNS(qname, labels) {
		c := newCred("DNS", "Tunnel Detection", srcIP, dstIP, dstPort)
		c.DNSQuery = qname
		return []Credential{c}
	}

	return nil
}

func isSuspiciousDNS(qname string, labels []string) bool {
	if len(qname) > 30 {
		return true
	}

	for _, label := range labels {
		if len(label) > 40 {
			return true
		}
		if len(label) > 10 && shannonEntropy(label) > 3.5 {
			return true
		}
	}

	if len(labels) > 6 {
		return true
	}

	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// --- SMB / NTLM ---

func ParseSMB(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	ntlm := extractNTLMFields(payload)
	if ntlm == nil {
		return nil
	}

	hashcatFormat := fmt.Sprintf("%s::%s:%s:%s:%s",
		ntlm.user, ntlm.domain,
		ntlm.challenge, ntlm.response,
		ntlm.ntproof)

	if ntlm.user == "" && ntlm.domain == "" {
		c := newCred("SMB", "NTLM Auth", srcIP, dstIP, dstPort)
		c.Hash = hashcatFormat
		c.Raw = "NTLMSSP authentication detected"
		return []Credential{c}
	}

	c := newCred("SMB", "NTLMv2", srcIP, dstIP, dstPort)
	c.Username = ntlm.domain + "\\" + ntlm.user
	c.Hash = hashcatFormat
	return []Credential{c}
}

type ntlmFields struct {
	domain    string
	user      string
	challenge string
	response  string
	ntproof   string
}

func extractNTLMFields(data []byte) *ntlmFields {
	text := string(data)

	if !strings.Contains(text, "NTLMSSP") {
		return nil
	}

	ntlm := &ntlmFields{}

	ntlmIdx := strings.Index(text, "NTLMSSP")
	if ntlmIdx < 0 {
		return ntlm
	}

	msgType := uint32(0)
	if len(data) > ntlmIdx+12 {
		msgType = uint32(data[ntlmIdx+8]) | uint32(data[ntlmIdx+9])<<8 |
			uint32(data[ntlmIdx+10])<<16 | uint32(data[ntlmIdx+11])<<24
	}

	if msgType == 3 {
		ntlm.domain = extractNTLMString(data, ntlmIdx+28)
		ntlm.user = extractNTLMString(data, ntlmIdx+36)
		ntlm.ntproof = extractNTLMHex(data, ntlmIdx)
	}

	if ntlm.domain != "" || ntlm.user != "" {
		return ntlm
	}

	for _, line := range strings.Split(text, "\x00") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\\") && len(line) < 100 && !strings.Contains(line, " ") {
			parts := strings.SplitN(line, "\\", 2)
			if len(parts) == 2 && len(parts[0]) < 50 && len(parts[1]) < 50 {
				ntlm.domain = parts[0]
				ntlm.user = parts[1]
				break
			}
		}
	}

	if ntlm.challenge == "" {
		ntlm.challenge = hexDump(data[ntlmIdx:min(ntlmIdx+40, len(data))], 16)
	}
	if ntlm.response == "" {
		ntlm.response = hexDump(data[ntlmIdx:min(ntlmIdx+200, len(data))], 100)
	}
	if ntlm.ntproof == "" {
		ntlm.ntproof = hexDump(data[ntlmIdx:min(ntlmIdx+50, len(data))], 16)
	}

	return ntlm
}

func extractNTLMString(data []byte, offset int) string {
	if offset+8 > len(data) {
		return ""
	}
	l := int(uint16(data[offset]) | uint16(data[offset+1])<<8)
	strOff := int(uint32(data[offset+4]) | uint32(data[offset+5])<<8 |
		uint32(data[offset+6])<<16 | uint32(data[offset+7])<<24)

	if l > 0 && l < 512 && strOff > 0 && strOff+l <= len(data) {
		raw := data[strOff : strOff+l]
		return decodeUTF16LE(raw)
	}
	return ""
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return strings.TrimRight(string(b), "\x00")
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(b[i]) | rune(b[i+1])<<8
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

func extractNTLMHex(data []byte, baseOffset int) string {
	if len(data) < baseOffset+40 {
		return hexDump(data[baseOffset:], 32)
	}
	return hexDump(data[baseOffset:baseOffset+32], 32)
}

// --- LDAP ---

func ParseLDAP(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	if cred := parseLDAPSimpleBind(payload, srcIP, dstIP, dstPort); cred != nil {
		return []Credential{*cred}
	}

	text := string(payload)
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(strings.ToLower(line), "cn=") && strings.Contains(strings.ToLower(line), "password") {
			c := newCred("LDAP", "Simple Bind", srcIP, dstIP, dstPort)
			c.Raw = strings.TrimSpace(line)
			return []Credential{c}
		}
	}
	return nil
}

func parseLDAPSimpleBind(data []byte, srcIP, dstIP string, dstPort uint16) *Credential {
	if len(data) < 10 {
		return nil
	}
	// BER sequence: 0x30
	if data[0] != 0x30 {
		return nil
	}

	offset := 2
	if data[1]&0x80 != 0 {
		numBytes := int(data[1] & 0x7f)
		if numBytes == 0 {
			return nil
		}
		if 2+numBytes > len(data) {
			return nil
		}
		offset = 2 + numBytes
	}
	if offset >= len(data) {
		return nil
	}

	// Message ID (integer: 0x02)
	if data[offset] != 0x02 {
		return nil
	}
	msgIDLen := int(data[offset+1])
	offset += 2 + msgIDLen
	if offset >= len(data) {
		return nil
	}

	// Bind request: application tag 0x60
	if data[offset] != 0x60 {
		return nil
	}
	offset += 2
	if offset >= len(data) {
		return nil
	}

	// Version (integer)
	if data[offset] != 0x02 {
		return nil
	}
	verLen := int(data[offset+1])
	offset += 2 + verLen
	if offset >= len(data) {
		return nil
	}

	// DN (octet string: 0x04)
	if data[offset] != 0x04 {
		return nil
	}
	dnLen := int(data[offset+1])
	offset += 2
	if offset+dnLen > len(data) {
		return nil
	}
	dn := string(data[offset : offset+dnLen])
	offset += dnLen
	if offset >= len(data) {
		return nil
	}

	// Simple auth (context tag 0x80)
	if data[offset] != 0x80 {
		return nil
	}
	pwLen := int(data[offset+1])
	offset += 2
	if offset+pwLen > len(data) {
		return nil
	}
	password := string(data[offset : offset+pwLen])

	if dn == "" || password == "" {
		return nil
	}

	c := newCred("LDAP", "Simple Bind", srcIP, dstIP, dstPort)
	c.Username = dn
	c.Password = password
	return &c
}

// --- FTP ---

func ParseFTP(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	text := string(payload)
	lines := strings.Split(text, "\r\n")

	var creds []Credential
	var lastUser string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)

		if strings.HasPrefix(upper, "USER ") {
			lastUser = strings.TrimSpace(line[5:])
		}

		if strings.HasPrefix(upper, "PASS ") && lastUser != "" {
			c := newCred("FTP", "Login", srcIP, dstIP, dstPort)
			c.Username = lastUser
			c.Password = strings.TrimSpace(line[5:])
			creds = append(creds, c)
			lastUser = ""
		}
	}

	return creds
}

// --- Telnet ---

func ParseTelnet(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	text := string(payload)

	cleaned := strings.Map(func(r rune) rune {
		if r < 32 && r != '\r' && r != '\n' {
			return -1
		}
		return r
	}, text)

	lines := strings.Split(cleaned, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "login:") || strings.Contains(lower, "username:") ||
			strings.Contains(lower, "password:") {
			c := newCred("TELNET", "Session", srcIP, dstIP, dstPort)
			c.Raw = line
			return []Credential{c}
		}
	}

	if len(cleaned) > 0 && len(cleaned) < 64 && !strings.ContainsAny(cleaned, "\xff\xfe\xfd") {
		trimmed := strings.TrimSpace(cleaned)
		if len(trimmed) > 0 && !strings.Contains(trimmed, " ") {
			c := newCred("TELNET", "Input", srcIP, dstIP, dstPort)
			c.Raw = trimmed
			return []Credential{c}
		}
	}

	return nil
}

func parseAuthPlain(b64 string) (string, string) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", ""
	}
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) >= 3 && parts[1] != "" {
		return parts[1], parts[2]
	}
	return "", ""
}

// --- POP3 ---

func ParsePOP3(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	text := string(payload)
	lines := strings.Split(text, "\r\n")

	var creds []Credential
	var lastUser string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)

		if strings.HasPrefix(upper, "USER ") {
			lastUser = strings.TrimSpace(line[5:])
		}

		if strings.HasPrefix(upper, "PASS ") && lastUser != "" {
			c := newCred("POP3", "Login", srcIP, dstIP, dstPort)
			c.Username = lastUser
			c.Password = strings.TrimSpace(line[5:])
			creds = append(creds, c)
			lastUser = ""
		}

		if strings.HasPrefix(upper, "AUTH PLAIN ") {
			user, pass := parseAuthPlain(line[11:])
			if user != "" {
				c := newCred("POP3", "AUTH PLAIN", srcIP, dstIP, dstPort)
				c.Username = user
				c.Password = pass
				creds = append(creds, c)
			}
		}
	}

	return creds
}

// --- IMAP ---

func ParseIMAP(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	text := string(payload)
	lines := strings.Split(text, "\r\n")

	var creds []Credential

	for _, line := range lines {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)

		loginIdx := strings.Index(upper, " LOGIN ")
		if loginIdx > 0 {
			rest := strings.TrimSpace(line[loginIdx+7:])
			user, pass := parseIMAPLoginArgs(rest)
			if user != "" {
				c := newCred("IMAP", "Login", srcIP, dstIP, dstPort)
				c.Username = user
				c.Password = pass
				creds = append(creds, c)
			}
		}

		if strings.Contains(upper, "AUTHENTICATE PLAIN ") {
			idx := strings.Index(upper, "AUTHENTICATE PLAIN ")
			user, pass := parseAuthPlain(line[idx+20:])
			if user != "" {
				c := newCred("IMAP", "AUTH PLAIN", srcIP, dstIP, dstPort)
				c.Username = user
				c.Password = pass
				creds = append(creds, c)
			}
		}
	}

	return creds
}

func parseIMAPLoginArgs(s string) (string, string) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return "", ""
	}

	if s[0] == '{' {
		end := strings.IndexByte(s, '}')
		if end > 1 && end+2 <= len(s) {
			s = s[end+2:]
		} else {
			return "", ""
		}
	}

	var user, pass string
	if len(s) > 0 && s[0] == '"' {
		end := strings.Index(s[1:], "\"")
		if end < 0 {
			return "", ""
		}
		user = s[1 : end+1]
		s = strings.TrimSpace(s[end+2:])
	} else {
		parts := strings.SplitN(s, " ", 2)
		user = parts[0]
		if len(parts) > 1 {
			s = strings.TrimSpace(parts[1])
		} else {
			return user, ""
		}
	}

	if len(s) > 0 && s[0] == '{' {
		end := strings.IndexByte(s, '}')
		if end > 1 && end+2 <= len(s) {
			s = s[end+2:]
		} else {
			return user, ""
		}
	}

	if len(s) > 0 && s[0] == '"' {
		end := strings.Index(s[1:], "\"")
		if end >= 0 {
			pass = s[1 : end+1]
		}
	} else {
		pass = strings.TrimSpace(s)
	}

	return user, pass
}

// --- SMTP ---

func ParseSMTP(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	text := string(payload)
	lines := strings.Split(text, "\r\n")

	var creds []Credential

	for _, line := range lines {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)

		if strings.HasPrefix(upper, "AUTH LOGIN ") {
			b64 := strings.TrimSpace(line[11:])
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err == nil {
				c := newCred("SMTP", "AUTH LOGIN", srcIP, dstIP, dstPort)
				c.Username = string(decoded)
				creds = append(creds, c)
			}
		}

		if strings.HasPrefix(upper, "AUTH PLAIN ") {
			user, pass := parseAuthPlain(line[11:])
			if user != "" {
				c := newCred("SMTP", "AUTH PLAIN", srcIP, dstIP, dstPort)
				c.Username = user
				c.Password = pass
				creds = append(creds, c)
			}
		}
	}

	return creds
}

// --- helpers ---

func hexDump(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}
	return fmt.Sprintf("%x", data)
}
