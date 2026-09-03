<div align="center">

# 📡 `driftnet2`
### Kernel-Level Network Sniffer, Credential Interceptor & Exposure Auditor

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![eBPF](https://img.shields.io/badge/eBPF-Linux_5.8+_XDP-FF6600?style=for-the-badge&logo=linux&logoColor=white)](https://ebpf.io)
[![Protocols](https://img.shields.io/badge/Protocols-9_Engines-00FF66?style=for-the-badge)]()
[![Format](https://img.shields.io/badge/NTLMv2-Hashcat_5600_Ready-blueviolet?style=for-the-badge)]()
[![Defense](https://img.shields.io/badge/Blue_Team-Exposure_Audit-red?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

<p align="center">
  <b>High-performance, kernel-level packet inspection, credential extraction, and defensive security auditing.</b><br>
  <sub>eBPF/XDP In-Kernel Capture · AF_PACKET / libpcap Fallback · 9 Protocols · Hashcat-Ready NTLMv2 · DNS Tunnel Heuristics · Blue-Team Remediation</sub>
</p>

<p align="center">
  <a href="#-live-terminal-demo"><b>[ Live Demo ]</b></a> &nbsp;•&nbsp;
  <a href="#-architecture-why-kernel-level-ebpfxdp-matters"><b>[ Architecture ]</b></a> &nbsp;•&nbsp;
  <a href="#-the-9-protocol-engines"><b>[ 9 Protocols ]</b></a> &nbsp;•&nbsp;
  <a href="#-mitre-attck-matrix"><b>[ MITRE ATT&CK ]</b></a> &nbsp;•&nbsp;
  <a href="#-quick-start"><b>[ Quick Start ]</b></a> &nbsp;•&nbsp;
  <a href="#-blue-team-exposure-audit"><b>[ Exposure Audit ]</b></a> &nbsp;•&nbsp;
  <a href="#-red-team-scenarios"><b>[ Red Team Ops ]</b></a> &nbsp;•&nbsp;
  <a href="#-comparison"><b>[ Comparison ]</b></a>
</p>

<p align="center">
  <img src="docs/demo.gif" alt="driftnet2 Kernel-Level Sniffer Demo" width="900" style="border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.12); box-shadow: 0 20px 40px -10px rgba(0,0,0,0.7);">
  <br><sub>Zero-Privilege Offline PCAP Replay & Credential Exposure Audit on Synthetic Test Captures</sub>
</p>

</div>

---

## ⚡ Architecture: Why Kernel-Level eBPF/XDP Matters

Traditional network sniffers (such as tcpdump, Wireshark, net-creds, and Bettercap) rely entirely on standard userspace packet capture APIs (e.g. `libpcap` or raw `AF_PACKET` sockets). In high-throughput 10G/40G enterprise networks, this model introduces severe drawbacks:

1. **Context Switching & Packet Drops:** Every frame must traverse the kernel's network stack, allocate an `sk_buff`, copy the buffer to userspace, and wake up listener threads. Under heavy load, buffers overflow and credentials are lost.
2. **Detection Footprint:** Standard promiscuous mode sockets and raw socket bindings leave clear operational artifacts across host monitoring agents and EDR telemetry.

**Driftnet2 bypasses these limitations using in-kernel eBPF and eXpress Data Path (XDP):**

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                  DRIFTNET2 CAPTURE ARCHITECTURE                             │
│                                                                                             │
│                         ┌───────────────────────────────┐                                   │
│                         │    Physical / Virtual NIC     │                                   │
│                         └───────────────┬───────────────┘                                   │
│                                         │                                                   │
│   ┌─────────────────────────────────────▼───────────────────────────────────────────────┐     │
│   │                        LINUX KERNEL SPACE (eBPF / XDP)                             │     │
│   │                                                                                    │     │
│   │   ┌────────────────────────┐                                                       │     │
│   │   │  XDP Hook (Driver Layer)│ ──> Drops non-target traffic immediately             │     │
│   │   └───────────┬────────────┘                                                       │     │
│   │               │                                                                    │     │
│   │   ┌───────────▼────────────┐                                                       │     │
│   │   │ BPF Ring Buffer Stream │ ──> In-kernel memory ring buffer (Zero socket alloc)  │     │
│   │   └───────────┬────────────┘                                                       │     │
│   └───────────────┼────────────────────────────────────────────────────────────────────┘     │
│                   │ Zero-Copy Kernel Stream                                                  │
│   ┌───────────────▼────────────────────────────────────────────────────────────────────┐     │
│   │                              USERSPACE ENGINE                                      │     │
│   │                                                                                    │     │
│   │   ┌────────────────────────────────────────────────────────────────────────────┐   │     │
│   │   │ Dual-Path Ingestion: eBPF Ring Buffer (Linux)  OR  AF_PACKET / libpcap     │   │     │
│   │   └─────────────────────────────────────┬──────────────────────────────────────┘   │     │
│   │                                         │                                          │     │
│   │   ┌─────────────────────────────────────▼──────────────────────────────────────┐   │     │
│   │   │                     9 PROTOCOL PARSING ENGINES                             │   │     │
│   │   │     HTTP · SMB (NTLMv2) · LDAP · FTP · Telnet · POP3 · IMAP · SMTP · DNS   │   │     │
│   │   └──────────────────┬──────────────────────────────────┬──────────────────────┘   │     │
│   │                      │                                  │                          │     │
│   │   ┌──────────────────▼───────────────┐  ┌───────────────▼──────────────────────┐   │     │
│   │   │       RED TEAM CAPTURE           │  │          BLUE TEAM AUDIT             │   │     │
│   │   │  Raw Passwords, Tokens, NTLMv2   │  │  Cleartext Exposure Risk Assessment  │   │     │
│   │   │  Hashcat-Ready Hashes · JSON/PCAP│  │  Severity Grading · Remediation Guide│   │     │
│   │   └──────────────────────────────────┘  └──────────────────────────────────────┘   │     │
│   └────────────────────────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **In-Kernel XDP Processing:** Evaluates frames directly in the network driver before kernel memory allocation, extracting candidate streams into high-speed BPF ring buffers.
- **Graceful Universal Fallback:** Automatically detects the operating environment. If eBPF/XDP is unavailable (macOS, BSD, or unprivileged containers), Driftnet2 falls back seamlessly to `AF_PACKET` / `libpcap` with zero difference in parser accuracy or output format.
- **Single Compact Binary:** Zero runtime dependencies. No Python interpreters, no Ruby gems, no shared library bloat. Ships as a single static binary (~5MB).

---

## 🎬 Live Terminal Demo

Run the end-to-end credential extraction and defensive audit offline against synthetic captures without root privileges:

```bash
# Clone and build
git clone https://github.com/jankesec/driftnet2.git && cd driftnet2
go build -ldflags="-s -w" -o driftnet2 ./cmd/driftnet2

# Analyze reproducible test PCAP with automated credential dump and exposure audit:
./driftnet2 -pcap examples/demo.pcap -output creds.json -audit
```

```text
    ____       _  ______            __   ___  
   / __ \_____(_)/ __/ /_____  ___ / /_ |__ \ 
  / / / / ___/ // /_/ __/ __ \/ _ \ __/ __/ / 
 / /_/ / /  / // __/ /_/ / / /  __/ /_ / __/  
/_____/_/  /_//_/    \__/_/ /_/\___/\__|____/ 

      kernel-level packet sniffer & credential extractor

[*] offline mode: examples/demo.pcap
[FTP] Login 192.0.2.10:198.51.100.20 → demo:Password123
[HTTP] Basic Auth 192.0.2.11:198.51.100.21 → demo:Password123
[POP3] Login 192.0.2.12:198.51.100.22 → demo@example.test:Password123
[IMAP] Login 192.0.2.13:198.51.100.23 → demo@example.test:Password123
[SMTP] AUTH PLAIN 192.0.2.14:198.51.100.24 → postmaster:smtppass
[TELNET] Session 192.0.2.15:198.51.100.25 → corp-router login: demo
[LDAP] Simple Bind 192.0.2.16:198.51.100.26 → cn=admin,dc=corp:ldappass
[SMB] NTLMv2 192.0.2.17:198.51.100.27 → jsmith::CORP:::4e544c4d53535000030000000
[DNS] Tunnel Detection 192.0.2.18:8.8.8.8 → DNS: TXlDMkV4ZmlsUGF5bG9hZERhdGFHb2VzSGVyZQ.c2.example.test

[*] 9 packets processed, 9 unique credentials found in examples/demo.pcap
[*] saved → creds.json

Credential Exposure Audit
=========================
9 findings — 7 High, 1 Medium, 1 Low

[HIGH] FTP — Cleartext password (1)
  Endpoints: 192.0.2.10 -> 198.51.100.20
  Fix: Disable plaintext FTP; use FTPS or SFTP.
...
```

---

## 📡 The 9 Protocol Engines

Driftnet2 extracts actionable credentials and session secrets across 9 protocols without requiring external dissectors:

| # | Protocol | Default Ports | Credential Type & Technique | Hashcat Mode | Example Output |
|:---:|:---|:---:|:---|:---:|:---|
| **1** | **HTTP** | `80, 8080, 443` | Basic Auth, Form POST fields, Bearer tokens, Session Cookies, Digest, NTLM | — | `admin:P@ssw0rd2026!` |
| **2** | **SMB / CIFS** | `445, 139` | NTLMv2 Challenge/Response handshake (User, Domain, Challenge, Response) | `5600` (NetNTLMv2) | `CORP\jsmith::...` |
| **3** | **LDAP** | `389` | Simple Bind cleartext credentials & DN paths | — | `cn=admin,dc=corp:SecretBind` |
| **4** | **FTP** | `21` | `USER` / `PASS` plaintext authentication commands | — | `ftpuser:Storage2026!` |
| **5** | **Telnet** | `23` | Interactive login prompt interrogation & user keystroke capture | — | `root:cisco123` |
| **6** | **POP3** | `110` | `USER` / `PASS`, `AUTH PLAIN` mailbox retrieval | — | `user@corp.com:MailPass!` |
| **7** | **IMAP** | `143` | `LOGIN` (quoted, literal, inline parameters) | — | `exec@corp.com:SecureMail1` |
| **8** | **SMTP** | `25, 587` | `AUTH LOGIN`, `AUTH PLAIN` MTA message transmission | — | `postmaster:SmtpSecret!` |
| **9** | **DNS** | `53` | Tunnel detection (entropy scoring, high-label length, Base64/Hex signatures) | — | `TXlDMk...c2.attacker.com` |

---

## 🎯 MITRE ATT&CK Matrix

Driftnet2 implements techniques from the MITRE ATT&CK Enterprise Matrix for adversary emulation and gap auditing:

| Tactic | Technique | ID | Driftnet2 Capability |
|:---|:---|:---:|:---|
| **Credential Access** | Network Sniffing | [T1040](https://attack.mitre.org/techniques/T1040/) | Live kernel-level eBPF & promiscuous packet sniffing |
| **Credential Access** | Adversary-in-the-Middle | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | NTLMv2 capture via SMB/LDAP authentication exchanges |
| **Credential Access** | Steal or Forge Kerberos / NTLM Hashes | [T1558](https://attack.mitre.org/techniques/T1558/) | Hashcat-ready NetNTLMv2 hash generation (`hashcat -m 5600`) |
| **Discovery** | Network Service Scanning | [T1046](https://attack.mitre.org/techniques/T1046/) | Unencrypted protocol service identification and endpoint mapping |
| **Command and Control** | Protocol Tunneling / DNS | [T1572](https://attack.mitre.org/techniques/T1572/) / [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Shannon entropy analysis for covert DNS tunnel detection |

---

## 🛡️ Blue Team: Exposure Audit (`-audit`)

Driftnet2 provides dual-mode output: while offensive operations focus on harvested credentials, defensive security teams can generate **actionable vulnerability assessments** directly from network captures:

```bash
# Generate full audit report and export machine-readable JSON:
./driftnet2 -pcap internal_traffic.pcap -audit -audit-output audit_report.json
```

### Risk Classification Model:
- **`[HIGH]` Exposure:** Cleartext passwords (FTP, HTTP Basic, POP3, IMAP, SMTP, LDAP Simple Bind) and crackable password hashes (SMB NTLMv2). Represents immediate credential compromise risk.
- **`[MEDIUM]` Exposure:** API Bearer tokens, active session cookies, and anomalous DNS tunneling indicators.
- **`[LOW]` Exposure:** Legacy unencrypted interactive sessions (Telnet banners, cleartext metadata).

### Sample Audit Remediation Output:
```text
Credential Exposure Audit
=========================
9 findings — 7 High, 1 Medium, 1 Low

[HIGH] SMB — Password hash (1)
  Endpoints: 192.0.2.17 -> 198.51.100.27
  Fix: Require SMB signing/encryption, restrict NTLM (prefer Kerberos), and enable Extended Protection for Authentication.

[HIGH] HTTP — Cleartext password (1)
  Endpoints: 192.0.2.11 -> 198.51.100.21
  Fix: Enforce HTTPS/HSTS; never send Basic auth, form credentials, or tokens over cleartext HTTP.

[HIGH] LDAP — Cleartext password (1)
  Endpoints: 192.0.2.16 -> 198.51.100.26
  Fix: Enforce LDAPS (TCP/636) or StartTLS; reject simple bind authentication over cleartext.

[MEDIUM] DNS — DNS tunnel indicator (1)
  Endpoints: 192.0.2.18 -> 8.8.8.8
  Fix: Investigate for tunneling/exfiltration; apply DNS filtering policy and query rate limiting.
```

---

## 🚀 Quick Start & Installation

### 1. Build from Source

```bash
# Clone repository
git clone https://github.com/jankesec/driftnet2.git && cd driftnet2

# Build optimized binary
make build
# Or via go build:
go build -ldflags="-s -w" -o driftnet2 ./cmd/driftnet2
```

### 2. Linux Kernel eBPF/XDP Compilation (Optional)

On Linux hosts with Clang/LLVM installed, compile the kernel hook:

```bash
make bpf    # Compiles bpf/xdp_sniff.c into xdp_sniff.o
```

> [!NOTE]
> Driftnet2 auto-locates `xdp_sniff.o` in the working directory, binary directory, or via `-bpf /path/to/xdp_sniff.o` / `DRIFTNET2_BPF` environment variable. If absent, it automatically uses high-performance `AF_PACKET`.

### 3. Operational Invocations

```bash
# Live sniffing on specific interface with protocol filtering and PCAP logging:
sudo ./driftnet2 -iface eth0 --proto http,smb,ldap -output creds.json -w live_capture.pcap

# Offline PCAP triage without root privileges:
./driftnet2 -pcap /path/to/dump.pcap --proto http,ftp,telnet

# Full compliance audit with JSON export:
./driftnet2 -pcap /path/to/dump.pcap -audit -audit-output audit_report.json
```

---

## ⚔️ Red Team Scenarios

### 1. Active Directory Domain Controller Sniffing
Positioned on a mirrored span port or compromised switch interface, capture domain authentication exchanges:

```bash
sudo ./driftnet2 -iface eth0 --proto smb,ldap -output domain_hashes.json
```

Extracted SMB hashes are directly formatted for Hashcat:
```bash
hashcat -m 5600 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

### 2. Lateral Movement Eavesdropping on Segmented Pivots
Deploy Driftnet2 as a self-contained static binary onto an authorized jump host to intercept administrative protocols:

```bash
# Transfer single binary over SSH:
scp driftnet2 operator@jumpbox:/tmp/

# Run headless with JSON streaming:
ssh operator@jumpbox "sudo /tmp/driftnet2 -iface eth1 --proto http,ftp,telnet -output /tmp/harvest.json"
```

### 3. Covert DNS C2 & Tunnel Hunting
Identify covert data exfiltration channels and C2 beacons operating over DNS TXT or subquery records:

```bash
sudo ./driftnet2 -iface eth0 --proto dns -v
```

---

## 🔬 Comparison

| Feature / Capability | **Driftnet2** | Bettercap | Net-Creds | PCredz | TShark | Zeek / Bro |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **In-Kernel eBPF/XDP Capture** | **Yes (Linux 5.8+)** | No | No | No | No | No |
| **Zero-Copy Ring Buffer** | **Yes** | No | No | No | No | No |
| **HTTP Basic/POST/Bearer/NTLM** | **Yes** | Basic | Yes | No | Manual Filter | Scripted |
| **SMB NTLMv2 Hashcat Output** | **Yes (`-m 5600`)** | No | No | No | Manual Filter | Scripted |
| **DNS Tunneling Heuristics** | **Yes (Entropy)** | No | No | No | No | Scripted |
| **Blue Team Exposure Audit** | **Yes (`-audit`)** | No | No | No | No | Third-party |
| **Offline PCAP Replay** | **Yes (0 Privileges)**| No | Yes | Yes | Yes | Yes |
| **Structured JSON Export** | **Yes** | Yes | No | No | Yes | Yes |
| **Binary Footprint** | **~5MB (Static Go)** | ~15MB | Python script | Python script | ~80MB+ | Complex Engine |
| **Cross-Platform Support** | **Linux / macOS / BSD**| Linux / macOS | Linux / macOS | Linux / macOS | All | Linux / macOS |

---

## 🛡️ Engineering Quality & Supply Chain

Every pull request and release is validated across Linux and macOS environments:

| Control | Gate & Verification |
|:---|:---|
| **Memory Safety & Race Testing** | `go test -race ./...` executed across all protocol parsers and buffer writers |
| **Static Code Analysis** | `golangci-lint` clean with 0 issues |
| **Security Auditing** | `gosec` static security scanner clean with 0 vulnerabilities |
| **eBPF Compilation** | Verified compilation in CI with `clang` and `llvm` |
| **Reproducibility** | Built-in test capture generator (`examples/gen`) ensuring deterministic parser tests |

---

## 📁 Project Structure

```
driftnet2/
├── bpf/
│   └── xdp_sniff.c            # In-kernel eBPF XDP filter & ring buffer engine
├── cmd/
│   └── driftnet2/
│       ├── main.go            # Unified CLI interface & session router
│       └── main_test.go       # Flag & configuration validation tests
├── pkg/
│   ├── audit/                 # Blue-team exposure auditor & remediation generator
│   ├── ebpf/                  # Cilium/ebpf loader & kernel ring buffer binding
│   ├── output/                # Live TUI visualizer & JSON streaming formatters
│   ├── protocol/              # 9 Protocol parsing engines (HTTP, SMB, DNS, etc.)
│   └── sniffer/               # Capture engine (XDP + AF_PACKET/libpcap) & PCAP writer
├── docs/                      # Technical architecture, eBPF specs & parser guides
├── examples/                  # Deterministic demo PCAP generator & sample capture
├── Makefile                   # Unified compilation, testing, and linting workflow
└── SECURITY.md                # Vulnerability disclosure & authorized-use policy
```

---

## 🔐 Cryptographic Identity & Author

Driftnet2 is researched and developed for authorized penetration testing, adversary emulation, and network security gap analysis.

```text
Author          : Sevban Dönmez (@jankesec)
Role            : Senior Cyber Security Consultant · Red Team & Offensive Security Researcher
Research Portal : https://jankesec.com
GitHub          : https://github.com/jankesec
PGP Fingerprint : FF0A 7D83 6751 CCE3 F9CC F574 FCF8 39FB 7F00 4626
GPG Key ID      : 5FDB257F4AAE8C3F
```

---

## ⚠️ Disclaimer

This tool is designed and distributed **exclusively for authorized network security assessments, penetration testing, defensive auditing, and academic research**. Intercepting network traffic or harvesting credentials without explicit, written authorization from network owners is illegal under computer crime statutes. The author assumes no liability for misuse, unauthorized monitoring, or regulatory violations.

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete terms.

<p align="center">
  <a href="https://www.buymeacoffee.com/sevbandonmez">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-sevbandonmez-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Buy Me A Coffee">
  </a>
</p>
