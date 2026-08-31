# Contributing to Driftnet2

Thanks for your interest in improving Driftnet2. This document covers local
setup, the quality gates, and the contribution workflow.

## Prerequisites

- **Go 1.24+**
- **libpcap headers** — `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel`
  (Fedora); preinstalled on macOS. Required because the capture path uses cgo
  via gopacket.
- **clang / llvm** — only needed to compile the eBPF/XDP object (`make bpf`) on
  Linux.

## Build, test, and lint

```bash
make build        # build the binary
make bpf          # compile the eBPF/XDP object (Linux)
make test         # go test ./...
make test-race    # go test -race ./...   (run this before opening a PR)
make lint         # golangci-lint
make sec          # gosec
make cover        # coverage profile + per-function summary
```

Install the linters once:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

## Quality gates

Every change must keep the following green — CI enforces all of them:

- `go build ./...`, `go vet ./...`
- `go test -race ./...`
- `golangci-lint run ./...` — **0 issues**
- `gosec -exclude=G115 ./...` — **0 issues** (G115 is excluded because the
  packet writer serializes into fixed-width on-wire fields; see the Makefile)
- `gofmt -s` clean

New behavior needs tests. Prefer table-driven tests, and test parsers against
malformed/truncated input as well as the happy path.

## Coding conventions

- Keep packages focused; the parsers live in `pkg/protocol`, capture in
  `pkg/sniffer`, output in `pkg/output`, and the eBPF loader in `pkg/ebpf`.
- Handle or explicitly discard (`_ =`) every error; justify any `#nosec` inline
  with a reason.
- Follow the existing style; run `make fmt` before committing.

## Commit & PR workflow

- Branch from `main`; use a descriptive branch name (`feat/…`, `fix/…`).
- Use [Conventional Commits](https://www.conventionalcommits.org/) messages
  (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `ci:`, `build:`).
- Open a PR against `main`; ensure CI is green.
- Describe what changed and how you verified it.

## Scope & responsible use

Driftnet2 is a security tool for **authorized** testing and research. Please keep
contributions aligned with that purpose and with the project's
[SECURITY.md](SECURITY.md) policy.
