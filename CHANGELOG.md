# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Portfolio-quality overhaul — engineering foundation, documentation, and a
defensive audit mode.

### Added
- Continuous integration (GitHub Actions): build + `go vet` + `-race` tests on a
  Linux/macOS matrix, golangci-lint, gosec, and a Linux eBPF-object compile job.
- `LICENSE` (MIT).
- Test suites for `cmd`, `pkg/output`, and `pkg/sniffer` (including a PCAP
  write→read round-trip), run under the race detector.
- golangci-lint (v2) and gosec configuration; `make` targets `test`,
  `test-race`, `vet`, `lint`, `fmt`, `cover`, `sec`.
- Reproducible offline demo: `examples/gen` generator and a committed
  `examples/demo.pcap` with synthetic credentials.
- `CONTRIBUTING.md`, `SECURITY.md`, and this changelog.
- `-bpf` flag and `DRIFTNET2_BPF` environment variable to locate the eBPF object.

### Changed
- Module path corrected to `github.com/jankesec/driftnet2`.
- Minimum Go version set to the real floor, **1.24** (required by cilium/ebpf).
- README rewritten: accurate protocol count (**9**), balanced positioning
  (measured claims instead of absolute "EDR-invisible" wording), build/test and
  reproducible-demo sections.

### Fixed
- eBPF object discovery no longer depends on the current working directory.
- `.gitignore` pattern `driftnet2` also matched the `cmd/driftnet2/` source
  directory; anchored to `/driftnet2`.
- Removed a provably-dead Telnet guard (`strings.ContainsAny` over invalid
  UTF-8) and a dead DNS parse offset; checked previously-ignored errors.

## [1.0.0] - 2026-06-13

### Added
- Initial public release: eBPF/XDP (Linux) and AF_PACKET/libpcap capture, nine
  cleartext protocol parsers (HTTP, DNS, SMB, LDAP, FTP, Telnet, POP3, IMAP,
  SMTP), DNS-tunnel heuristics, and TUI / JSON / PCAP output.

[Unreleased]: https://github.com/jankesec/driftnet2/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jankesec/driftnet2/releases/tag/v1.0.0
