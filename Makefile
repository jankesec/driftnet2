.PHONY: all bpf build build-macos clean deps test test-race vet lint fmt cover sec

BPF_SRC  = bpf/xdp_sniff.c
BPF_OUT  = bpf/xdp_sniff.o
GO_BIN   = driftnet2
# Multiarch include dir where linux-libc-dev ships <asm/types.h> (Debian/Ubuntu).
BPF_ARCH ?= $(shell uname -m)
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   = -s -w \
	-X github.com/jankesec/driftnet2/internal/buildinfo.Version=$(VERSION) \
	-X github.com/jankesec/driftnet2/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/jankesec/driftnet2/internal/buildinfo.Date=$(BUILD_DATE)

all: bpf build

bpf:
	@echo "[*] compiling eBPF XDP program (arch: $(BPF_ARCH))..."
	clang -O2 -g -target bpf -I/usr/include/$(BPF_ARCH)-linux-gnu -c $(BPF_SRC) -o $(BPF_OUT)

build:
	@echo "[*] building Go binary..."
	go build -ldflags="$(LDFLAGS)" -o $(GO_BIN) ./cmd/driftnet2

build-macos:
	@echo "[*] building macOS binary (libpcap mode)..."
	go build -ldflags="$(LDFLAGS)" -o $(GO_BIN) ./cmd/driftnet2

clean:
	rm -f $(BPF_OUT) $(GO_BIN)

deps:
	@echo "[*] installing Go dependencies..."
	go mod tidy

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

# G115 is excluded: every int -> uint16/uint32 conversion in pkg/sniffer
# serializes into a fixed-width on-wire field (pcap record header, IP/UDP
# length fields) whose width is defined by the wire format itself.
# G304/G703 (operator-provided file paths) are justified inline via #nosec.
sec:
	gosec -exclude=G115 ./...
