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
	text := string(payload)
	if strings.Contains(text, "NTLMSSP") {
		return []Credential{{
			Protocol: "SMB",
			Type:     "NTLM Auth",
			SrcIP:    srcIP, DstIP: dstIP, DstPort: dstPort,
			Hash: hexDump(payload, 64),
			Raw:  "NTLMSSP authentication detected",
		}}
	}
	return nil
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
