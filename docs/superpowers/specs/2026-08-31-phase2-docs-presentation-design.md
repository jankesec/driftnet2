# Driftnet2 — Phase 2: Documentation & Presentation (Design / Spec)

**Date:** 2026-08-31
**Status:** Approved (design), ready for implementation
**Depends on:** Phase 1 (quality foundation)

## Goal

Make the repo read like a credible, professionally-maintained project. Accuracy
pass + balanced positioning (keep the red-team utility, drop overclaims), plus
the standard OSS documentation set and a release pipeline. No feature changes.

## Positioning decision

Tone = **balanced professional** (user choice). Keep red-team scenarios, but:
frame everything as authorized testing/research, and replace absolute claims
("zero EDR footprint", "invisible to EDR/XDR") with measured, caveated wording
(XDP runs in-kernel, ahead of userspace pcap-based tooling — a visibility
reduction, not an invisibility guarantee).

## Work items

1. **README rewrite** (`README.md`)
   - **Accuracy:** it parses **9** protocols (HTTP, DNS, SMB, LDAP, FTP, Telnet,
     POP3, IMAP, SMTP), not 8 — fix the tagline, intro, protocols badge, and
     "8 protocol parsers" in the structure section.
   - **Truthful badges:** Go badge must match `go.mod` (`go 1.26`).
   - **Tone:** soften EDR-invisibility claims in the tagline, intro, architecture
     note, and comparison table (row "EDR invisible" → "In-kernel XDP capture").
   - **New CLI:** document the `-bpf` flag and `DRIFTNET2_BPF`.
   - **Add:** a "Build & Test" section (make targets: build, bpf, test,
     test-race, lint, sec, cover) and a runnable "Demo" section (see item 6).
   - **Authorized-use:** reframe the "pivot host" scenario for authorized
     engagements; keep the disclaimer, expand it slightly.

2. **CONTRIBUTING.md** — dev setup (Go 1.26, libpcap, clang for eBPF), the make
   targets, the lint/gosec gates, commit/PR conventions, how tests are run.

3. **CHANGELOG.md** — Keep a Changelog format. An `Unreleased` section covering
   this overhaul (Phase 1 + Phase 2 + Phase 3), and a `1.0.0` entry for the
   existing tag.

4. **SECURITY.md** — authorized-use statement, scope, and a vulnerability
   reporting channel (GitHub Security Advisories / private contact).

5. **Release pipeline** (`.github/workflows/release.yml`)
   - Trigger on `v*` tags. Native-runner matrix (linux/amd64 on ubuntu,
     darwin/arm64 + darwin/amd64 on macOS) — cgo/libpcap rules out simple cross
     compilation, so build each on its own OS.
   - Produce a compressed binary per target + a `SHA256SUMS` file, and attach
     them to a GitHub Release. Cannot be executed here (no tag push); validate
     YAML and logic only.

6. **Runnable demo** (`examples/`)
   - `examples/gen/main.go`: a tiny generator that writes a sample PCAP with
     **obviously-synthetic** credentials (RFC 5737 `192.0.2.0/24` / `198.51.100.0/24`
     addresses; creds like `demo:Password123`). Reuses `pkg/sniffer.PCAPWriter`.
   - Commit the generated `examples/demo.pcap`.
   - README shows `./driftnet2 -pcap examples/demo.pcap` with expected output.
   - This is a reproducible demo (better than a GIF for a security tool) and
     doubles as living documentation. Verify the tool actually parses it.

## Optional improvement (attempt, low-risk)

Try lowering the `go.mod` floor from `1.26` to a more widely-available version
(e.g. `1.23`) and **verify** the build via `GOTOOLCHAIN`. If deps or the build
require a higher floor, keep `1.26`. Whatever floor holds, the README badge must
match it.

## Verification

- `go build ./...` / `go test ./...` still green.
- `./driftnet2 -pcap examples/demo.pcap` prints the synthetic credentials.
- `release.yml` is valid YAML.
- README internal links (LICENSE, CONTRIBUTING, SECURITY, CHANGELOG) resolve.
- No remaining "8 protocols" / absolute EDR-invisibility claims.

## Non-goals

- Publishing an actual GitHub Release (happens on a real tag push by the user).
- Any behavior/feature change (Phase 3 owns the audit mode).
