# Driftnet2 — Phase 3: Credential Exposure Audit Mode (Design / Spec)

**Date:** 2026-09-01
**Status:** Approved (design), ready for implementation
**Depends on:** Phase 1, Phase 2

## Goal

Add a **defensive / blue-team** mode that turns captured credential events into a
prioritized **exposure report** — what was exposed, how bad it is, and how to
fix it — instead of only dumping raw credentials. This reframes the tool as a
network hygiene auditor and adds real, testable value without any new offensive
capability.

## New package: `pkg/audit`

```go
type Severity string // "Critical" | "High" | "Medium" | "Low" | "Info"

type Finding struct {
    Protocol    string   `json:"protocol"`
    Exposure    string   `json:"exposure"`     // short category, e.g. "Cleartext password"
    Severity    Severity `json:"severity"`
    Count       int      `json:"count"`        // number of credential events
    Endpoints   []string `json:"endpoints"`    // unique "src -> dst", capped
    Remediation string   `json:"remediation"`
}

type Report struct {
    Findings []Finding      `json:"findings"`
    Totals   map[Severity]int `json:"totals"`
}

func Analyze(creds []protocol.Credential) *Report
func (r *Report) Text() string
func (r *Report) JSON() ([]byte, error)
```

### Severity mapping (by credential shape)

- `Password != ""` → **High** — full credentials in cleartext.
- `Hash != ""` → **High** — capturable NTLM/Digest hash (offline crack / relay).
- `Token != ""` → **Medium** — session token / cookie (hijack).
- `DNSQuery != ""` → **Medium** — possible tunnel / exfiltration.
- otherwise → **Low**.

### Grouping

Group by `(Protocol, Exposure)`. `Count` = events in the group; `Endpoints` =
unique `"src -> dst"` strings (capped at 10, with a "+N more" note in text
output). Findings sorted by severity (Critical→Low), then Protocol.

### Remediation (per protocol)

FTP→FTPS/SFTP; Telnet→SSH; POP3/IMAP/SMTP→enforce TLS / disable cleartext auth;
HTTP→HTTPS/HSTS, no Basic/token over cleartext; LDAP→LDAPS/StartTLS, avoid simple
bind; SMB→signing/encryption, restrict NTLM, prefer Kerberos; DNS→investigate
tunneling, apply DNS monitoring/filtering.

## CLI wiring (`cmd/driftnet2`)

- `-audit` (bool): after capture (offline end, or live shutdown), print the
  audit report built from the collected credentials.
- `-audit-output <file>` (string): also write the report as JSON to `<file>`
  (0600, like `-output`).

Existing raw output is unchanged; the report is additive.

## Testing (`pkg/audit/audit_test.go`, TDD)

- Severity mapping for password / hash / token / dns / bare cases.
- Grouping + `Count` + endpoint dedup and cap.
- `Totals` aggregation.
- `Text()` contains severity, protocol, remediation.
- `JSON()` round-trips into the documented shape.
- Empty input → empty findings, valid (non-nil) report.

## Docs

- README: add an "Audit mode" subsection with a real `-audit` run over
  `examples/demo.pcap`; add `pkg/audit` to the structure.
- CHANGELOG: add the audit mode under Added.

## Verification

- `go test -race ./...`, `golangci-lint`, `gosec -exclude=G115` all green.
- `./driftnet2 -pcap examples/demo.pcap -audit` prints a sensible report.

## Non-goals

- No new capture/parse capability, no active/offensive features.
- No severity scoring config file (could be a later enhancement).
