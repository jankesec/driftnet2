# Driftnet2 Phase 1 — Quality Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn driftnet2 into an engineering-credible baseline — correct metadata, working license, CI, static analysis, broader tests, robust config — with no feature changes.

**Architecture:** Small, targeted changes across existing packages plus new test files, CI config, and repo metadata. One cross-file signature change threads a resolved eBPF-object path through `main → sniffer.NewXDPLive → ebpf.NewXDPSniffer`. Everything else is additive (tests, config, LICENSE, Makefile targets, workflow).

**Tech Stack:** Go 1.26, gopacket (cgo/libpcap), cilium/ebpf, GitHub Actions, golangci-lint, gosec.

## Global Constraints

- Module path (verbatim): `github.com/jankesec/driftnet2`
- Go directive (verbatim): `go 1.26` (no patch pin)
- License: MIT, copyright `Copyright (c) 2026 Sevban Dönmez`
- Agent MUST NOT push to GitHub — local commits on branch `feat/phase1-quality` only.
- Dev machine is macOS/arm64; Linux-only eBPF compile + XDP runtime are validated in CI, not locally.
- macOS `sed` in-place edits require `sed -i ''`.
- Follow existing code style; keep changes within Phase 1 scope.
- Every task ends green: `go build ./... && go vet ./... && go test -race ./...`.

---

### Task 1: Align module path and Go version

**Files:**
- Modify: `go.mod`
- Modify: every `*.go` importing `github.com/byjanke/driftnet2/...`
  (`cmd/driftnet2/main.go`, `pkg/output/json.go`, `pkg/output/tui.go`, `pkg/sniffer/xdp.go`)

**Interfaces:**
- Consumes: nothing.
- Produces: canonical import prefix `github.com/jankesec/driftnet2` used by all later tasks' test files.

- [ ] **Step 1: Rewrite module path and imports**

```bash
cd /Users/johndoe/Downloads/driftnet2
sed -i '' 's#module github.com/byjanke/driftnet2#module github.com/jankesec/driftnet2#' go.mod
sed -i '' 's#^go 1\.26\.1#go 1.26#' go.mod
grep -rl 'github.com/byjanke/driftnet2' --include='*.go' . \
  | xargs sed -i '' 's#github.com/byjanke/driftnet2#github.com/jankesec/driftnet2#g'
```

- [ ] **Step 2: Verify no stale references remain**

Run: `grep -rn 'byjanke' --include='*.go' go.mod || echo CLEAN`
Expected: `CLEAN`

- [ ] **Step 3: Build, vet, test**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all pass (`ok ... pkg/protocol`, others `[no test files]`).

- [ ] **Step 4: Commit**

```bash
git add go.mod cmd pkg
git commit -m "refactor: align module path to jankesec, relax go directive to 1.26"
```

---

### Task 2: Add LICENSE and fix README build instructions

**Files:**
- Create: `LICENSE`
- Modify: `README.md` (clone URL line only)

**Interfaces:**
- Consumes: nothing.
- Produces: `LICENSE` at repo root (makes the README license badge/link resolve).

- [ ] **Step 1: Write the MIT LICENSE**

```bash
cd /Users/johndoe/Downloads/driftnet2
cat > LICENSE <<'EOF'
MIT License

Copyright (c) 2026 Sevban Dönmez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
```

- [ ] **Step 2: Fix the clone URL in README**

```bash
sed -i '' 's#github.com/byjanke/driftnet2#github.com/jankesec/driftnet2#g' README.md
grep -n 'jankesec/driftnet2' README.md
```
Expected: the clone-command line now shows `jankesec`.

- [ ] **Step 3: Commit**

```bash
git add LICENSE README.md
git commit -m "docs: add MIT LICENSE and correct clone URL"
```

---

### Task 3: Working-directory-independent eBPF object discovery

**Files:**
- Modify: `pkg/ebpf/loader.go` (func `NewXDPSniffer`, lines ~64-69)
- Modify: `pkg/sniffer/xdp.go` (func `NewXDPLive`, lines ~15-16)
- Modify: `cmd/driftnet2/main.go` (flag block ~30-37, XDP detect ~64-71, XDP construct ~86-95, add helper + `path/filepath` import)
- Create: `cmd/driftnet2/main_test.go`

**Interfaces:**
- Produces:
  - `ebpf.NewXDPSniffer(iface, objPath string) (*XDPSniffer, error)`
  - `sniffer.NewXDPLive(iface, objPath string) (*xdpWrapper, error)`
  - `resolveBPFObject(flagPath string) (path string, found bool)` in package `main`

- [ ] **Step 1: Write the failing test for `resolveBPFObject`**

Create `cmd/driftnet2/main_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBPFObjectFlag(t *testing.T) {
	dir := t.TempDir()
	obj := filepath.Join(dir, "custom.o")
	if err := os.WriteFile(obj, []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := resolveBPFObject(obj)
	if !ok || got != obj {
		t.Fatalf("flag path: got (%q,%v), want (%q,true)", got, ok, obj)
	}
}

func TestResolveBPFObjectEnv(t *testing.T) {
	dir := t.TempDir()
	obj := filepath.Join(dir, "xdp_sniff.o")
	if err := os.WriteFile(obj, []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DRIFTNET2_BPF", obj)
	got, ok := resolveBPFObject("")
	if !ok || got != obj {
		t.Fatalf("env path: got (%q,%v), want (%q,true)", got, ok, obj)
	}
}

func TestResolveBPFObjectFlagBeatsEnv(t *testing.T) {
	dir := t.TempDir()
	flagObj := filepath.Join(dir, "flag.o")
	envObj := filepath.Join(dir, "env.o")
	for _, p := range []string{flagObj, envObj} {
		if err := os.WriteFile(p, []byte{0}, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DRIFTNET2_BPF", envObj)
	got, ok := resolveBPFObject(flagObj)
	if !ok || got != flagObj {
		t.Fatalf("precedence: got (%q,%v), want (%q,true)", got, ok, flagObj)
	}
}

func TestResolveBPFObjectMissing(t *testing.T) {
	t.Setenv("DRIFTNET2_BPF", "")
	if got, ok := resolveBPFObject(filepath.Join(t.TempDir(), "nope.o")); ok {
		t.Fatalf("missing object should not resolve, got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/driftnet2/ -run TestResolveBPFObject -v`
Expected: FAIL / build error — `undefined: resolveBPFObject`.

- [ ] **Step 3: Add the helper and `path/filepath` import in `main.go`**

Add `"path/filepath"` to the import block. Append this function to `cmd/driftnet2/main.go`:

```go
// resolveBPFObject locates the compiled XDP object independent of the current
// working directory. Order: explicit flag, DRIFTNET2_BPF env, next to the
// executable, then ./bpf/xdp_sniff.o as a last resort.
func resolveBPFObject(flagPath string) (string, bool) {
	var candidates []string
	if flagPath != "" {
		candidates = append(candidates, flagPath)
	}
	if env := os.Getenv("DRIFTNET2_BPF"); env != "" {
		candidates = append(candidates, env)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "bpf", "xdp_sniff.o"))
	}
	candidates = append(candidates, filepath.Join("bpf", "xdp_sniff.o"))
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, true
		}
	}
	return "", false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/driftnet2/ -run TestResolveBPFObject -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Thread the path through the eBPF loader**

In `pkg/ebpf/loader.go`, change the signature and both hardcoded paths:

```go
func NewXDPSniffer(iface, objPath string) (*XDPSniffer, error) {
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%s not found — run 'make bpf' first", objPath)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
```

- [ ] **Step 6: Thread the path through the sniffer wrapper**

In `pkg/sniffer/xdp.go`:

```go
func NewXDPLive(iface, objPath string) (*xdpWrapper, error) {
	xdp, err := ebpf.NewXDPSniffer(iface, objPath)
```

- [ ] **Step 7: Wire the flag and resolution into `main.go`**

Add the flag in the flag block:

```go
	bpfPath := flag.String("bpf", "", "path to compiled eBPF object (default: auto-detect)")
```

Replace the XDP-detection block:

```go
	mode := "AF_PACKET"
	hasXDP := false
	bpfObj := ""
	if runtime.GOOS == "linux" {
		if p, ok := resolveBPFObject(*bpfPath); ok {
			mode = "XDP"
			hasXDP = true
			bpfObj = p
		}
	}
```

Update the XDP construction call (in the `if hasXDP` block):

```go
		sniff, err = sniffer.NewXDPLive(*iface, bpfObj)
```

- [ ] **Step 8: Build, vet, race-test the whole module**

Run: `go build ./... && go vet ./... && go test -race ./...`
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add cmd pkg
git commit -m "fix: resolve eBPF object independent of working directory (-bpf flag, DRIFTNET2_BPF)"
```

---

### Task 4: Unit tests for `parseProtoSet`

**Files:**
- Modify: `cmd/driftnet2/main_test.go` (append)

**Interfaces:**
- Consumes: `parseProtoSet(string) map[string]bool` (existing).

- [ ] **Step 1: Append the tests**

```go
func TestParseProtoSetSubset(t *testing.T) {
	got := parseProtoSet("http,dns,smb")
	for _, p := range []string{"http", "dns", "smb"} {
		if !got[p] {
			t.Errorf("expected %q in set", p)
		}
	}
	if got["ftp"] {
		t.Errorf("did not expect ftp in set")
	}
}

func TestParseProtoSetTrimAndLower(t *testing.T) {
	got := parseProtoSet(" HTTP , DnS ")
	if !got["http"] || !got["dns"] {
		t.Errorf("expected normalized http/dns, got %v", got)
	}
}
```

- [ ] **Step 2: Run**

Run: `go test ./cmd/driftnet2/ -run TestParseProtoSet -v`
Expected: PASS (2 tests).

- [ ] **Step 3: Commit**

```bash
git add cmd/driftnet2/main_test.go
git commit -m "test: cover parseProtoSet normalization"
```

---

### Task 5: Tests for `pkg/output` (JSON + TUI)

**Files:**
- Create: `pkg/output/json_test.go`
- Create: `pkg/output/tui_test.go`

**Interfaces:**
- Consumes: `WriteJSON([]protocol.Credential, string) error`, `NewTerminalUI(iface, mode string) *TerminalUI`, `(*TerminalUI).PrintCredential(protocol.Credential)`.

- [ ] **Step 1: Write `json_test.go`**

```go
package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jankesec/driftnet2/pkg/protocol"
)

func TestWriteJSONRoundTrip(t *testing.T) {
	creds := []protocol.Credential{{
		Protocol: "ftp", Type: "login",
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 21,
		Username: "u", Password: "p",
		Timestamp: time.Unix(0, 0).UTC(),
	}}
	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteJSON(creds, path); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Metadata struct {
			Tool  string `json:"tool"`
			Count int    `json:"count"`
		} `json:"metadata"`
		Credentials []protocol.Credential `json:"credentials"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Metadata.Tool != "driftnet2" {
		t.Errorf("tool = %q, want driftnet2", decoded.Metadata.Tool)
	}
	if decoded.Metadata.Count != 1 {
		t.Errorf("count = %d, want 1", decoded.Metadata.Count)
	}
	if len(decoded.Credentials) != 1 || decoded.Credentials[0].Password != "p" {
		t.Errorf("credentials round-trip mismatch: %+v", decoded.Credentials)
	}
}

func TestWriteJSONPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteJSON(nil, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms = %v, want 0600", info.Mode().Perm())
	}
}
```

- [ ] **Step 2: Write `tui_test.go`**

```go
package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jankesec/driftnet2/pkg/protocol"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestPrintCredentialPassword(t *testing.T) {
	ui := NewTerminalUI("eth0", "AF_PACKET")
	c := protocol.Credential{
		Protocol: "ftp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 21,
		Username: "bob", Password: "secret",
	}
	out := captureStdout(t, func() { ui.PrintCredential(c) })
	if !strings.Contains(out, "bob") || !strings.Contains(out, "secret") {
		t.Errorf("output missing creds: %q", out)
	}
	if !strings.Contains(out, "→") {
		t.Errorf("output missing arrow: %q", out)
	}
}
```

- [ ] **Step 3: Run**

Run: `go test ./pkg/output/ -v`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add pkg/output/json_test.go pkg/output/tui_test.go
git commit -m "test: cover JSON export round-trip and TUI credential rendering"
```

---

### Task 6: Tests for `pkg/sniffer` (PCAP round-trip + selectors)

**Files:**
- Create: `pkg/sniffer/sniffer_test.go`

**Interfaces:**
- Consumes: `NewPCAPWriter(string, layers.LinkType) (*PCAPWriter, error)`, `(*PCAPWriter).WritePacket(*RawPacket) error`, `NewPCAPSniffer(string) (*AFPacketSniffer, error)`, `(*AFPacketSniffer).Events() <-chan *RawPacket`, `IsInterfaceValid(string) bool`, `LinkTypeFromSniffer(interface{}) layers.LinkType`.

- [ ] **Step 1: Write the round-trip + selector tests**

```go
package sniffer

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestPCAPWriterRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rt.pcap")
	w, err := NewPCAPWriter(path, layers.LinkTypeRaw)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	pkt := &RawPacket{
		Timestamp: time.Unix(1, 0),
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   1234,
		DstPort:   21,
		Protocol:  6, // TCP
		Payload:   []byte("USER bob\r\n"),
	}
	if err := w.WritePacket(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := NewPCAPSniffer(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer s.Close()

	var got []*RawPacket
	for p := range s.Events() { // drains to EOF, lets the reader goroutine exit
		got = append(got, p)
	}
	if len(got) != 1 {
		t.Fatalf("read back %d packets, want 1", len(got))
	}
	if got[0].SrcIP != "10.0.0.1" || got[0].DstIP != "10.0.0.2" {
		t.Errorf("ips: got %s -> %s", got[0].SrcIP, got[0].DstIP)
	}
	if string(got[0].Payload) != "USER bob\r\n" {
		t.Errorf("payload = %q", got[0].Payload)
	}
}

func TestIsInterfaceValidUnknown(t *testing.T) {
	if IsInterfaceValid("definitely-not-a-real-iface-xyz") {
		t.Error("unknown interface should be invalid")
	}
}

func TestLinkTypeFromSnifferDefault(t *testing.T) {
	if got := LinkTypeFromSniffer("not a sniffer"); got != layers.LinkTypeRaw {
		t.Errorf("default link type = %v, want Raw", got)
	}
}
```

- [ ] **Step 2: Run with race**

Run: `go test -race ./pkg/sniffer/ -v`
Expected: PASS (3 tests). (Needs libpcap — present on macOS and installed in CI.)

- [ ] **Step 3: Commit**

```bash
git add pkg/sniffer/sniffer_test.go
git commit -m "test: PCAP write/read round-trip and sniffer selectors"
```

---

### Task 7: golangci-lint config and fix findings

**Files:**
- Create: `.golangci.yml`
- Modify: `pkg/sniffer/writer.go` (remove unused const), `cmd/driftnet2/main.go` (check two ignored errors)

**Interfaces:** none (cleanup).

- [ ] **Step 1: Add `.golangci.yml`**

```yaml
run:
  timeout: 5m
linters:
  enable:
    - errcheck
    - govet
    - ineffassign
    - staticcheck
    - unused
    - misspell
```

- [ ] **Step 2: Remove the unused `linkTypeRaw` const**

In `pkg/sniffer/writer.go`, delete the block:

```go
const (
	linkTypeRaw = 101
)
```

- [ ] **Step 3: Check the ignored error in `runOffline`**

In `cmd/driftnet2/main.go`, replace `output.WriteJSON(allCreds, jsonOut)` with:

```go
		if err := output.WriteJSON(allCreds, jsonOut); err != nil {
			log.Printf("json: %v", err)
		}
```

- [ ] **Step 4: Check the ignored error in the live capture loop**

Replace `pcapW.WritePacket(pkt)` with:

```go
				if err := pcapW.WritePacket(pkt); err != nil {
					log.Printf("pcap write: %v", err)
				}
```

- [ ] **Step 5: Install (if needed) and run golangci-lint**

```bash
command -v golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
$(go env GOPATH)/bin/golangci-lint run ./...
```
Expected: no issues. Fix any remaining `errcheck` findings by the same pattern (handle the error, or `_ =` with a short reason comment for genuine fire-and-forget cleanup). If the installed linter cannot parse the Go 1.26 toolchain, see the plan's Risks note.

- [ ] **Step 6: Re-run build/vet/test to confirm no regressions**

Run: `go build ./... && go vet ./... && go test -race ./...`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add .golangci.yml pkg/sniffer/writer.go cmd/driftnet2/main.go
git commit -m "chore: add golangci-lint config and resolve findings"
```

---

### Task 8: gosec scan and documented suppressions

**Files:**
- Possibly modify: source files needing narrowly-scoped `//nolint:gosec // reason`
- Optionally create: `.gosec.json` (only if an exclusion is genuinely needed)

**Interfaces:** none.

- [ ] **Step 1: Install (if needed) and run gosec**

```bash
command -v gosec || go install github.com/securego/gosec/v2/cmd/gosec@latest
$(go env GOPATH)/bin/gosec ./...
```

- [ ] **Step 2: Resolve findings**

For each finding: fix real issues; for behavior inherent to a network credential tool (e.g. G103 unsafe, subprocess, or secret-looking test fixtures) add a single-line `//nolint:gosec // <reason>` at the offending line, or list the rule ID under an `.gosec.json` exclude with a comment. Do not blanket-disable.

- [ ] **Step 3: Re-run to confirm clean**

Run: `$(go env GOPATH)/bin/gosec ./...`
Expected: `Issues: 0` (or only documented, justified suppressions).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: gosec clean (documented suppressions where inherent)"
```

---

### Task 9: Makefile developer targets

**Files:**
- Modify: `Makefile`

**Interfaces:** none.

- [ ] **Step 1: Add phony targets**

Add to the `.PHONY` line: `test test-race vet lint fmt cover`. Append:

```make
test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
```

- [ ] **Step 2: Smoke-test the targets**

Run: `make vet test`
Expected: both succeed.

- [ ] **Step 3: Ignore coverage artifact**

Append `coverage.out` to `.gitignore`.

- [ ] **Step 4: Commit**

```bash
git add Makefile .gitignore
git commit -m "build: add test/vet/lint/fmt/cover Makefile targets"
```

---

### Task 10: GitHub Actions CI + README badge

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `README.md` (add CI badge near the top badge row)

**Interfaces:** none.

- [ ] **Step 1: Write the workflow**

```yaml
name: CI

on:
  push:
    branches: [main, "feat/**"]
  pull_request:
    branches: [main]

jobs:
  build-test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Install libpcap (Linux)
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libpcap-dev
      - run: go build ./...
      - run: go vet ./...
      - run: go test -race ./...

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Install libpcap
        run: sudo apt-get update && sudo apt-get install -y libpcap-dev
      - uses: golangci/golangci-lint-action@v6
        with:
          version: latest

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Install libpcap
        run: sudo apt-get update && sudo apt-get install -y libpcap-dev
      - name: Run gosec
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          "$(go env GOPATH)/bin/gosec" ./...

  ebpf:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install clang/llvm
        run: sudo apt-get update && sudo apt-get install -y clang llvm
      - name: Compile eBPF object
        run: make bpf
      - name: Assert object exists
        run: test -f bpf/xdp_sniff.o
```

- [ ] **Step 2: Add the CI badge to README**

Add under the existing badge row (top of `README.md`):

```markdown
[![CI](https://github.com/jankesec/driftnet2/actions/workflows/ci.yml/badge.svg)](https://github.com/jankesec/driftnet2/actions/workflows/ci.yml)
```

- [ ] **Step 3: Validate workflow YAML locally**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('YAML OK')"`
Expected: `YAML OK`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "ci: add GitHub Actions (build/test/lint/gosec + eBPF compile) and CI badge"
```

---

## Final verification (after all tasks)

- [ ] `go build ./... && go vet ./... && go test -race ./...` — all green.
- [ ] `golangci-lint run ./...` — clean.
- [ ] `gosec ./...` — clean or documented.
- [ ] `LICENSE` exists; README badges/links resolve; no `byjanke` references remain.
- [ ] `git log --oneline` shows the task commits on `feat/phase1-quality`.
- [ ] Hand back to the user to review and push (agent does not push).

## Risks / notes

- **Go 1.26 tooling:** if `golangci-lint`/`gosec` cannot parse the 1.26 toolchain, use the newest available release; if still incompatible, note it in the PR and keep `go vet` + `staticcheck` as the enforced gate for now. Do not downgrade the module's `go` directive to satisfy a linter.
- **cgo/libpcap:** every CI job that compiles the module installs `libpcap-dev`; the `ebpf` job does not (it only runs `clang`).
- **PCAP round-trip:** relies on gopacket decoding `LinkTypeRaw` IPv4 — matches the writer's reconstructed packets and `LinkTypeFromSniffer`'s default.
