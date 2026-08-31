// Package audit turns captured credential events into a prioritized,
// defensive exposure report: what was exposed, how severe it is, and how to
// remediate it. It adds no capture or offensive capability — it only reasons
// over credentials already collected by the parsers.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jankesec/driftnet2/pkg/protocol"
)

// Severity is an ordinal risk level for a finding.
type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Info     Severity = "Info"
)

func rank(s Severity) int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// severityOrder is the display/summary order for severities.
var severityOrder = []Severity{Critical, High, Medium, Low, Info}

// Finding is one aggregated class of credential exposure.
type Finding struct {
	Protocol    string   `json:"protocol"`
	Exposure    string   `json:"exposure"`
	Severity    Severity `json:"severity"`
	Count       int      `json:"count"`
	Endpoints   []string `json:"endpoints"`
	Remediation string   `json:"remediation"`
}

// Report is the full audit result.
type Report struct {
	Findings []Finding        `json:"findings"`
	Totals   map[Severity]int `json:"totals"`
}

// classify derives the exposure category and severity from a credential's shape.
func classify(c protocol.Credential) (exposure string, sev Severity) {
	switch {
	case c.Password != "":
		return "Cleartext password", High
	case c.Hash != "":
		return "Password hash", High
	case c.Token != "":
		return "Session token", Medium
	case c.DNSQuery != "":
		return "DNS tunnel indicator", Medium
	default:
		return "Other exposure", Low
	}
}

var remediation = map[string]string{
	"FTP":    "Disable plaintext FTP; use FTPS or SFTP.",
	"TELNET": "Replace Telnet with SSH.",
	"POP3":   "Enforce TLS (POP3S or STARTTLS) and disable cleartext authentication.",
	"IMAP":   "Enforce TLS (IMAPS or STARTTLS) and disable cleartext authentication.",
	"SMTP":   "Enforce TLS (SMTPS or STARTTLS) and disable cleartext AUTH.",
	"HTTP":   "Enforce HTTPS/HSTS; never send Basic auth, form credentials, or tokens over cleartext HTTP.",
	"LDAP":   "Use LDAPS or StartTLS; avoid simple bind over cleartext.",
	"SMB":    "Require SMB signing/encryption, restrict NTLM (prefer Kerberos), and enable Extended Protection for Authentication.",
	"DNS":    "Investigate for tunneling/exfiltration; apply DNS monitoring and filtering policy.",
}

func remediationFor(proto string) string {
	if r, ok := remediation[strings.ToUpper(proto)]; ok {
		return r
	}
	return "Enforce transport encryption for this protocol and eliminate cleartext credentials."
}

// Analyze aggregates credential events into a prioritized Report. It never
// returns nil.
func Analyze(creds []protocol.Credential) *Report {
	type acc struct {
		finding *Finding
		seen    map[string]bool
	}
	groups := map[string]*acc{}
	var order []string

	for _, c := range creds {
		exposure, sev := classify(c)
		key := strings.ToUpper(c.Protocol) + "|" + exposure
		a := groups[key]
		if a == nil {
			a = &acc{
				finding: &Finding{
					Protocol:    c.Protocol,
					Exposure:    exposure,
					Severity:    sev,
					Remediation: remediationFor(c.Protocol),
				},
				seen: map[string]bool{},
			}
			groups[key] = a
			order = append(order, key)
		}
		a.finding.Count++
		ep := fmt.Sprintf("%s -> %s", c.SrcIP, c.DstIP)
		if !a.seen[ep] {
			a.seen[ep] = true
			a.finding.Endpoints = append(a.finding.Endpoints, ep)
		}
	}

	r := &Report{Totals: map[Severity]int{}}
	for _, key := range order {
		f := groups[key].finding
		r.Findings = append(r.Findings, *f)
		r.Totals[f.Severity]++
	}

	sort.SliceStable(r.Findings, func(i, j int) bool {
		if ri, rj := rank(r.Findings[i].Severity), rank(r.Findings[j].Severity); ri != rj {
			return ri > rj
		}
		return r.Findings[i].Protocol < r.Findings[j].Protocol
	})

	return r
}

const endpointDisplayCap = 10

// Text renders a human-readable report.
func (r *Report) Text() string {
	var b strings.Builder
	b.WriteString("Credential Exposure Audit\n")
	b.WriteString("=========================\n")

	if len(r.Findings) == 0 {
		b.WriteString("No credential exposure findings.\n")
		return b.String()
	}

	var parts []string
	for _, s := range severityOrder {
		if n := r.Totals[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	fmt.Fprintf(&b, "%d findings — %s\n\n", len(r.Findings), strings.Join(parts, ", "))

	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %s — %s (%d)\n",
			strings.ToUpper(string(f.Severity)), f.Protocol, f.Exposure, f.Count)

		shown := f.Endpoints
		extra := 0
		if len(shown) > endpointDisplayCap {
			extra = len(shown) - endpointDisplayCap
			shown = shown[:endpointDisplayCap]
		}
		if len(shown) > 0 {
			line := strings.Join(shown, ", ")
			if extra > 0 {
				line += fmt.Sprintf(" (+%d more)", extra)
			}
			b.WriteString("  Endpoints: " + line + "\n")
		}
		b.WriteString("  Fix: " + f.Remediation + "\n\n")
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}

// JSON renders the report as indented JSON. HTML escaping is disabled so the
// "src -> dst" endpoints stay readable.
func (r *Report) JSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
