<h1 align="center">Driftnet2</h1>

<p align="center">
  <b>Kernel-level network sniffer &amp; credential extractor.</b><br>
  9 cleartext protocols · eBPF/XDP capture on Linux · cross-platform via libpcap · a defensive audit mode.
</p>

<p align="center">
  <a href="https://github.com/jankesec/driftnet2/actions/workflows/ci.yml"><img src="https://github.com/jankesec/driftnet2/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/jankesec/driftnet2"><img src="https://goreportcard.com/badge/github.com/jankesec/driftnet2" alt="Go Report Card"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go" alt="Go"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/protocols-9-green" alt="Protocols">
  <a href="https://ebpf.io"><img src="https://img.shields.io/badge/eBPF-Linux%205.8+-orange" alt="eBPF"></a>
</p>

> **Authorized use only.** For penetration testing, red-team engagements, and
> security research **with explicit authorization**, and for auditing networks
> you own or operate. Capturing traffic you are not authorized to capture is
> illegal — see the [Disclaimer](#disclaimer).

Driftnet2 extracts credentials, session tokens, and NTLM hashes from **live or
captured** traffic. On Linux it can capture **in-kernel via eBPF/XDP** (ahead of
userspace pcap-based tooling); on macOS/BSD — and as a Linux fallback — it uses
**AF_PACKET/libpcap**. Nine cleartext protocol parsers feed a red-team credential
dump *and* a blue-team [exposure audit](#blue-team-exposure-audit).

---

## See it work (30 seconds, no privileges)

A sample capture of **synthetic** credentials (RFC 5737 addresses, fake secrets)
ships in the repo — every parser, end to end, offline:

```bash
go build -o driftnet2 ./cmd/driftnet2
./driftnet2 -pcap examples/demo.pcap
```

```
[FTP]    Login          192.0.2.10:198.51.100.20 → demo:Password123
[HTTP]   Basic Auth     192.0.2.11:198.51.100.21 → demo:Password123
[POP3]   Login          192.0.2.12:198.51.100.22 → demo@example.test:Password123
[IMAP]   Login          192.0.2.13:198.51.100.23 → demo@example.test:Password123
[SMTP]   AUTH PLAIN     192.0.2.14:198.51.100.24 → postmaster:smtppass
[TELNET] Session        192.0.2.15:198.51.100.25 → corp-router login: demo
[LDAP]   Simple Bind    192.0.2.16:198.51.100.26 → cn=admin,dc=corp:ldappass
[SMB]    NTLMv2         192.0.2.17:198.51.100.27 → jsmith::CORP:...
[DNS]    Tunnel         192.0.2.18:8.8.8.8       → TXlDMkV4...c2.example.test

[*] 9 packets processed, 9 unique credentials found
```

Add `-audit` to turn that into a prioritized, remediation-oriented report →
[Blue Team: Exposure Audit](#blue-team-exposure-audit).

---

## Highlights

- **Two capture layers** — eBPF/XDP in the kernel on Linux, AF_PACKET/libpcap
  everywhere (auto-detected, graceful fallback). Same parsers, same output.
- **9 protocols** — HTTP (Basic / form / Bearer / Cookie / Digest / NTLM), SMB
  (NTLMv2, hashcat format), LDAP, FTP, Telnet, POP3, IMAP, SMTP, plus DNS-tunnel
  heuristics.
- **Red *and* blue** — dump credentials for an engagement, or run `-audit` to
  report cleartext-exposure risk with severity and fixes.
- **Portable output** — live terminal dashboard, JSON export, and PCAP
  read/write for offline analysis.
- **Single static-ish binary** — no Python/Ruby runtime.
- **Engineered to ship** — CI on Linux + macOS, `golangci-lint` clean, `gosec`
  clean, race-tested; the eBPF object is compiled in CI. See [Quality](#quality).

## Contents

[Demo](#see-it-work-30-seconds-no-privileges) ·
[Highlights](#highlights) ·
[Architecture](#architecture) ·
[Credentials](#extracted-credentials) ·
[Install](#install) ·
[Audit mode](#blue-team-exposure-audit) ·
[Red-team](#red-team-scenarios) ·
[Build &amp; Test](#build--test) ·
[Quality](#quality) ·
[Comparison](#comparison) ·
[Structure](#project-structure)

---

## Architecture

```
                  ┌──────────────────┐
                  │   NETWORK CARD   │
                  └────────┬─────────┘
                           │
              ┌────────────▼────────────┐
              │  eBPF XDP Hook (kernel) │  in-kernel capture (Linux),
              │  filter → ring buffer   │  ahead of userspace pcap tooling
              └────────────┬────────────┘
                           │ ring buffer
              ┌────────────▼────────────┐
              │       Go Userspace      │
              │  Protocol parsers (9)   │
              │  → credential model     │
              │  → TUI / JSON / PCAP     │
              │  → exposure audit        │
              └─────────────────────────┘
```

On non-Linux hosts (and when the compiled XDP object is absent) the same parsers
run over an AF_PACKET/libpcap capture path — identical output, no kernel component.

## Extracted Credentials

| # | Protocol | Port | Credential Type | Example |
|---|----------|------|----------------|---------|
| 1 | **HTTP** | 80,443 | Basic, POST form, Bearer, Cookie, Digest, NTLM | `demo:Password123` |
| 2 | **DNS** | 53 | Tunnel detection (long labels, high entropy) | `TXlD…c2.example` |
| 3 | **SMB** | 445 | NTLMv2 hash (user, domain, hashcat format) | `jsmith::CORP:…` |
| 4 | **LDAP** | 389 | Simple bind | `cn=admin,dc=corp:pass` |
| 5 | **FTP** | 21 | USER / PASS | `demo:Password123` |
| 6 | **Telnet** | 23 | Login prompt / input | `login: demo` |
| 7 | **POP3** | 110 | USER / PASS, AUTH PLAIN | `demo@example:pass` |
| 8 | **IMAP** | 143 | LOGIN (quoted / literal / inline) | `demo@example:pass` |
| 9 | **SMTP** | 25,587 | AUTH LOGIN / PLAIN | `postmaster:pass` |

## Install

```bash
git clone https://github.com/jankesec/driftnet2 && cd driftnet2
go build -o driftnet2 ./cmd/driftnet2
```

Prebuilt binaries for tagged releases are attached to the
[Releases](https://github.com/jankesec/driftnet2/releases) page (with checksums).

**Live sniff (needs privileges):**

```bash
sudo ./driftnet2 -iface eth0 --proto http,ftp,smb -output creds.json -w capture.pcap
```

**Offline analysis (no privileges):**

```bash
./driftnet2 -pcap dump.pcap --proto http,dns,ftp
```

**Linux eBPF/XDP mode (root, kernel 5.8+):**

```bash
make bpf                       # compile the eBPF object (needs clang)
sudo ./driftnet2 -iface eth0   # auto-detects the XDP object, else AF_PACKET
```

The XDP object is located independent of the working directory: pass
`-bpf /path/to/xdp_sniff.o`, set `DRIFTNET2_BPF`, or place it next to the binary.

> **Note on stealth.** In-kernel XDP capture reduces the footprint seen by
> userspace pcap-based tools; it is **not** an invisibility guarantee against
> kernel-aware EDR/host monitoring.

---

## Blue Team: Exposure Audit

`-audit` (live or offline) reports the cleartext credential exposure observed —
severity and remediation instead of a raw dump. `-audit-output report.json`
also writes JSON.

```bash
./driftnet2 -pcap examples/demo.pcap -audit
```

```
Credential Exposure Audit
=========================
9 findings — 7 High, 1 Medium, 1 Low

[HIGH] SMB — Password hash (1)
  Endpoints: 192.0.2.17 -> 198.51.100.27
  Fix: Require SMB signing/encryption, restrict NTLM (prefer Kerberos), and enable Extended Protection for Authentication.

[HIGH] FTP — Cleartext password (1)
  Endpoints: 192.0.2.10 -> 198.51.100.20
  Fix: Disable plaintext FTP; use FTPS or SFTP.

[MEDIUM] DNS — DNS tunnel indicator (1)
  Endpoints: 192.0.2.18 -> 8.8.8.8
  Fix: Investigate for tunneling/exfiltration; apply DNS monitoring and filtering policy.

  … 9 findings total (7 High, 1 Medium, 1 Low) …
```

Severity is derived from what was captured (cleartext password / hash → High,
session token / DNS-tunnel indicator → Medium), grouped by protocol and endpoint.

## Red Team: Scenarios

> Only within the scope of an authorized engagement.

**Catch cleartext protocols on an internal segment:**

```bash
sudo ./driftnet2 -iface eth1 --proto ftp,telnet,pop3,smtp -w internal.pcap
```

**Sniff domain-controller traffic for NTLM hashes:**

```bash
sudo ./driftnet2 -iface eth0 --proto smb,ldap -output hashes.json
# [SMB] 10.0.0.42 → 10.0.0.1:445   CORP\jsmith::...   (hashcat-ready)
```

**Hunt DNS tunnels / C2:**

```bash
sudo ./driftnet2 -iface eth0 --proto dns -v
```

**Collect on an authorized pivot, retrieve for reporting:**

```bash
scp driftnet2 user@pivot:/tmp/ && ssh user@pivot "sudo /tmp/driftnet2 -iface eth1 -output /tmp/creds.json"
```

---

## Build & Test

```bash
make build        # build the binary (-s -w)
make bpf          # compile the eBPF/XDP object (Linux, needs clang)
make test-race    # go test -race ./...
make lint         # golangci-lint
make sec          # gosec
make cover        # coverage profile + summary
```

Requirements: Go 1.24+, libpcap headers (`libpcap-dev` / preinstalled on macOS),
and `clang`/`llvm` for the optional eBPF object.

## Quality

Every push runs the full gate on Linux **and** macOS:

- `go build` + `go vet` + `go test -race` across all packages
- **golangci-lint** — 0 issues · **gosec** — 0 issues
- the **eBPF/XDP object is compiled** in CI (Linux + clang)
- parser logic is unit-tested (all 9 protocols), plus a PCAP write→read
  round-trip; the audit engine is ~85% covered

The demo above (`examples/demo.pcap`) is generated by `examples/gen` and doubles
as a reproducible integration check for every parser. The **runtime** capture
paths (live AF_PACKET and eBPF/XDP), which CI only compiles, can be validated on
a Linux host with `sudo ./scripts/live-poc.sh`.

## Comparison

| | driftnet2 | bettercap | net-creds | pcredz | tshark |
|---|:---:|:---:|:---:|:---:|:---:|
| In-kernel eBPF/XDP capture | ✓ | — | — | — | — |
| HTTP Basic + POST + Bearer + Cookie | ✓ | basic | ✓ | — | manual |
| SMB NTLM (hashcat format) | ✓ | — | — | — | manual |
| DNS tunnel detection | ✓ | — | — | — | — |
| FTP / Telnet / POP3 / IMAP / SMTP | ✓ | — | — | — | manual |
| Exposure audit (severity + fixes) | ✓ | — | — | — | — |
| Offline PCAP analysis | ✓ | — | ✓ | ✓ | ✓ |
| JSON export | ✓ | ✓ | — | — | — |
| Single binary (no Python/Ruby) | ✓ ~5MB | ✓ ~15MB | — | — | ✓ |
| Cross-platform (Linux/macOS/BSD) | ✓ | ✓ | ✓ | — | ✓ |

Reflects the authors' understanding of each tool's defaults; others may cover
some cells via plugins or manual dissectors.

## Project Structure

```
driftnet2/
├── bpf/xdp_sniff.c            eBPF XDP program (IPv4 + IPv6)
├── cmd/driftnet2/main.go      CLI entry point
├── pkg/
│   ├── ebpf/                  cilium/ebpf loader + ring buffer
│   ├── sniffer/               live/offline capture + PCAP writer  (+ tests)
│   ├── protocol/              9 protocol parsers                  (+ tests)
│   ├── audit/                 credential-exposure audit report    (+ tests)
│   └── output/                terminal dashboard + JSON export     (+ tests)
├── examples/                  reproducible demo generator + sample PCAP
├── .github/workflows/         CI + release pipelines
└── Makefile
```

## Contributing & Security

- Dev setup, workflow, and gates → [CONTRIBUTING.md](CONTRIBUTING.md)
- Vulnerability reporting + authorized-use policy → [SECURITY.md](SECURITY.md)
- Release history → [CHANGELOG.md](CHANGELOG.md)

## Disclaimer

Driftnet2 is intended for **authorized penetration testing, red-team assessments,
defensive auditing, and security research only**. You are responsible for
complying with all applicable laws and for obtaining explicit authorization
before capturing any traffic you do not own. The authors accept no liability for
misuse.

## License

[MIT](LICENSE) © Sevban Dönmez
