package protocol

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

type Credential struct {
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Raw      string `json:"raw,omitempty"`
	DNSQuery string `json:"dns_query,omitempty"`
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

func ParseHTTP(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	text := string(payload)
	var creds []Credential

	lines := strings.Split(text, "\r\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "Authorization: Basic ") {
			b64 := strings.TrimPrefix(line, "Authorization: Basic ")
			b64 = strings.TrimSpace(b64)
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					creds = append(creds, Credential{
						Protocol: "HTTP",
						Type:     "Basic Auth",
						SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
						Username: parts[0], Password: parts[1],
					})
				}
			}
		}

		if strings.HasPrefix(line, "Authorization: Bearer ") {
			token := strings.TrimPrefix(line, "Authorization: Bearer ")
			creds = append(creds, Credential{
				Protocol: "HTTP",
				Type:     "Bearer Token",
				SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
				Token: strings.TrimSpace(token),
			})
		}

		if strings.HasPrefix(strings.ToLower(line), "cookie:") {
			cookieStr := strings.TrimPrefix(strings.ToLower(line), "cookie:")
			for _, c := range strings.Split(cookieStr, ";") {
				c = strings.TrimSpace(c)
				if strings.Contains(c, "session") || strings.Contains(c, "token") ||
					strings.Contains(c, "auth") || strings.Contains(c, "sid") {
					creds = append(creds, Credential{
						Protocol: "HTTP",
						Type:     "Session Cookie",
						SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
						Token: c,
					})
				}
			}
		}
	}

	for _, line := range lines {
		parsed, err := url.ParseQuery(line)
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
								creds = append(creds, Credential{
									Protocol: "HTTP",
									Type:     "POST Form",
									SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
									Username: userVals[0], Password: pwVals[0],
								})
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
	if len(qname) > 30 {
		return []Credential{{
			Protocol: "DNS",
			Type:     "Tunnel Detection",
			SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
			DNSQuery: qname,
		}}
	}

	return nil
}

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
		return []Credential{{
			Protocol: "SMB",
			Type:     "NTLM Auth",
			SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
			Hash: hashcatFormat,
			Raw:  "NTLMSSP authentication detected",
		}}
	}

	return []Credential{{
		Protocol: "SMB",
		Type:     "NTLMv2",
		SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
		Username: ntlm.domain + "\\" + ntlm.user,
		Hash:     hashcatFormat,
	}}
}

type ntlmFields struct {
	domain     string
	user       string
	challenge  string
	response   string
	ntproof    string
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
		ntlm.ntproof = extractNTLMHex(data, ntlmIdx, 0)
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
		return strings.TrimRight(string(raw), "\x00")
	}
	return ""
}

func extractNTLMHex(data []byte, baseOffset, _ int) string {
	if len(data) < baseOffset+40 {
		return hexDump(data[baseOffset:], 32)
	}
	return hexDump(data[baseOffset:baseOffset+32], 32)
}

func ParseLDAP(payload []byte, srcIP, dstIP string, dstPort uint16) []Credential {
	text := string(payload)
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(strings.ToLower(line), "cn=") && strings.Contains(strings.ToLower(line), "password") {
			return []Credential{{
				Protocol: "LDAP",
				Type:     "Simple Bind",
				SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
				Raw: strings.TrimSpace(line),
			}}
		}
	}
	return nil
}

func hexDump(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}
	return fmt.Sprintf("%x", data)
}
