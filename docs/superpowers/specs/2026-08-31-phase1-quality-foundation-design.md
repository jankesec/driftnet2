# Driftnet2 — Phase 1: Quality Foundation (Design / Spec)

**Date:** 2026-08-31
**Status:** Approved (design), ready for implementation planning
**Author:** brainstormed with Claude Code

---

## Context

`driftnet2` (repo: `github.com/jankesec/driftnet2`) is a Go network sniffer &
credential extractor (~2,300 LoC) with 8 protocol parsers, eBPF/XDP + AF_PACKET
capture, PCAP read/write, and TUI/JSON output. It is a legitimate dual-use
security tool intended for **authorized** penetration testing and research, with
an authorization disclaimer in the README.

The code builds cleanly, `go vet` passes, and the `protocol` package has 21
passing tests. The goal of this effort is to make the project a **credible
portfolio piece** for a security professional, via a phased, holistic overhaul.

This document specifies **Phase 1: Quality Foundation** only. Phases 2
(documentation/presentation) and 3 (new capabilities) get their own specs later.

## Goals (Phase 1)

Turn the repo into an engineering-credible baseline: correct metadata, working
license, continuous integration, static analysis, broader test coverage, and
robust configuration — without changing the tool's feature set.

### Success criteria

- `go build ./...`, `go vet ./...`, and `go test -race ./...` all pass locally.
- `golangci-lint run` passes with the committed config.
- `gosec ./...` passes (with justified, documented suppressions where a rule
  fires on inherent credential-handling behavior).
- Module path and all imports match the canonical repo (`jankesec`).
- A `LICENSE` file exists and the README license badge/link resolves.
- A GitHub Actions CI workflow exists that runs build + vet + test(-race) +
  lint + gosec on a linux/macOS matrix, with `libpcap` available for cgo.
- XDP object discovery no longer depends on the current working directory.
- New tests cover `pkg/output`, `pkg/sniffer` (file/pure logic), and `cmd`
  proto-set parsing.

## Non-goals (deferred to later phases)

- README rewrite / positioning pass, CONTRIBUTING, CHANGELOG, SECURITY.md — **Phase 2**.
- GitHub Releases, cross-compiled binaries, checksums, demo GIF/asciinema — **Phase 2**.
- New protocols/features, large architectural refactors (full dependency
  injection, etc.) — **Phase 3**.
- Pushing to GitHub — done by the user, not by the agent (see Constraints).

## Constraints

- **No push by the agent.** All work lands as local commits on the
  `feat/phase1-quality` branch. Publishing/modifying the public repo is the
  user's explicit action (or explicitly authorized with their credentials).
- **Local machine is macOS/arm64.** Linux-only eBPF (`clang -target bpf`) and
  Linux XDP runtime cannot be executed here; correctness for those paths is
  covered by CI (build/compile) and code review, not local runtime.
- Follow existing code style and structure; keep changes focused on Phase 1.

---

## Work items

### 1. Metadata & configuration correctness

1.1 **LICENSE** — add MIT `LICENSE` at repo root.
   Copyright line: `Copyright (c) 2026 Sevban Dönmez`
   (matches the public commit-author identity; swap to `jankesec` handle on request).

1.2 **Module path** — in `go.mod`, change
   `module github.com/byjanke/driftnet2` → `module github.com/jankesec/driftnet2`.
   Update every import path `github.com/byjanke/driftnet2/...` →
   `github.com/jankesec/driftnet2/...` across the codebase.

1.3 **Go version** — `go.mod` `go 1.26.1` → `go 1.26` (drop the patch pin so
   contributors/CI with any 1.26.x toolchain can build).

1.4 **README clone URL** — the single line that breaks the build instructions
   (`git clone https://github.com/byjanke/driftnet2`) → `jankesec`. Full README
   pass is Phase 2; this is a targeted correctness fix only.

### 2. Robust XDP object discovery

Current: `os.Stat("bpf/xdp_sniff.o")` in `cmd/driftnet2/main.go` — only finds
the object when the process is launched from the repo root.

New resolution order (first hit wins):
1. `-bpf <path>` CLI flag, if provided.
2. `DRIFTNET2_BPF` environment variable, if set.
3. `<dir-of-executable>/bpf/xdp_sniff.o`.
4. `./bpf/xdp_sniff.o` (current behavior, as final fallback).

Extract this into a small helper (e.g. `resolveBPFObject(flag string) (string, bool)`)
so it is unit-testable without a Linux runtime. Only the discovery/selection
logic is tested; actual XDP attach remains Linux/root-only.

### 3. Test expansion (run with `-race`)

Add tests for the currently-untested packages. Focus on pure logic and
file-based I/O; live capture (needs root + a real interface) stays out of scope.

3.1 **`pkg/output`**
   - JSON export (`json.go`): serialize a known `[]Credential` and assert the
     structure/fields are stable and complete (round-trip decode).
   - TUI (`tui.go`): test any pure formatting helpers (e.g. row/line
     formatting) that can be exercised without a live terminal.

3.2 **`pkg/sniffer`**
   - `writer.go`: PCAP write → read round-trip through a temp file; assert
     packet count/bytes/link-type survive.
   - `LinkTypeFromSniffer` and other pure selectors.
   - If feasible, a tiny committed fixture `.pcap` exercised end-to-end through
     the offline path (parse → credentials) as an integration test.
   - `IsInterfaceValid`: test only in an OS-independent way (e.g. a clearly
     invalid name returns false); avoid asserting on host-specific interfaces.

3.3 **`cmd/driftnet2`**
   - `parseProtoSet`: table-driven tests (default set, subset, unknown tokens,
     whitespace/case handling).

3.4 **`pkg/protocol`** — add edge-case tests only where a clear gap exists
   (e.g. malformed/truncated input returns no panic and no false credential).

### 4. Static analysis config

4.1 **`.golangci.yml`** — enable a sensible linter set (govet, staticcheck,
   errcheck, ineffassign, unused, gofmt/goimports, misspell, revive-lite).
   Keep it green against the current code; fix trivial findings, and disable or
   `//nolint` with a written reason for anything that conflicts with the tool's
   nature.

4.2 **gosec** — a credential sniffer legitimately handles secret-looking data
   and does low-level packet work; some gosec rules (e.g. hardcoded-credential
   heuristics on test fixtures, unsafe/`G103`, subprocess) may fire. Resolve
   real issues; for inherent ones add a narrowly-scoped `//nolint:gosec // reason`
   or a documented exclusion in CI config. Document the rationale in a short
   comment near each suppression.

### 5. CI — GitHub Actions

`.github/workflows/ci.yml`, triggered on `push` and `pull_request` to `main`
(and the feature branch during development):

- **Matrix:** `ubuntu-latest`, `macos-latest`.
- **Steps:** checkout → setup-go (1.26.x) → install `libpcap` headers
  (`libpcap-dev` on Ubuntu; preinstalled on macOS) → `go build ./...` →
  `go vet ./...` → `go test -race ./...`.
- **Lint job:** `golangci-lint` (official action) on ubuntu.
- **Security job:** `gosec` on ubuntu.
- **eBPF compile (ubuntu only, optional/allowed-to-be-required):** install
  `clang`/`llvm`, run `make bpf`, assert `bpf/xdp_sniff.o` is produced. This
  validates the Linux-only path that cannot run on the dev machine.

Pin action versions; keep the workflow readable. The commands it runs must all
pass locally first (except the Linux-only eBPF compile, validated in CI).

### 6. Makefile & README badge

6.1 **Makefile** — add phony targets: `test` (`go test ./...`),
   `test-race` (`go test -race ./...`), `vet`, `lint` (`golangci-lint run`),
   `fmt` (`gofmt -s -w` / `goimports`), `cover`
   (`go test -coverprofile` + `go tool cover`). Keep existing `bpf`, `build`,
   `build-macos`, `clean`, `deps` targets.

6.2 **README** — add a CI status badge; the existing license badge starts
   resolving once `LICENSE` exists. No other README changes in Phase 1.

---

## Verification plan

Local (macOS/arm64):
- `go build ./...` — clean.
- `go vet ./...` — clean.
- `go test -race ./...` — all packages pass; new packages have tests.
- `golangci-lint run` — clean.
- `gosec ./...` — clean (or only documented suppressions).
- `make lint test-race` — green.
- YAML lint / sanity read of `ci.yml`.

CI (validated after the user pushes):
- Full matrix build/test/lint/gosec + Linux eBPF compile.

The agent will NOT push. Verification of the GitHub Actions run itself happens
after the user publishes the branch.

## Risks / open questions

- **gosec noise:** may require several justified suppressions; acceptable as
  long as each is documented and no real issue is masked.
- **cgo/libpcap in CI:** gopacket needs libpcap headers; the workflow must
  install them or the build fails on the runner. Covered explicitly above.
- **Fixture PCAP:** if producing a clean, license-safe fixture is fiddly, fall
  back to constructing packets in-code or gopacket-crafted bytes rather than
  committing a captured file. Not a blocker.
- **Copyright holder name:** defaulted to `Sevban Dönmez`; trivially swappable.

## Out-of-band decisions already made

- Canonical import path: `github.com/jankesec/driftnet2` (matches `origin`).
- Branch: `feat/phase1-quality`.
- License: MIT (unchanged from stated intent).
