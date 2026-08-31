.PHONY: all bpf build build-macos clean deps test test-race vet lint fmt cover sec

BPF_SRC = bpf/xdp_sniff.c
BPF_OUT = bpf/xdp_sniff.o
GO_BIN  = driftnet2

all: bpf build

bpf:
	@echo "[*] compiling eBPF XDP program..."
	clang -O2 -target bpf -c $(BPF_SRC) -o $(BPF_OUT) -I/usr/include/x86_64-linux-gnu 2>/dev/null || \
	clang -O2 -target bpf -c $(BPF_SRC) -o $(BPF_OUT)

build:
	@echo "[*] building Go binary..."
	go build -ldflags="-s -w" -o $(GO_BIN) ./cmd/driftnet2

build-macos:
	@echo "[*] building macOS binary (AF_PACKET mode only)..."
	go build -ldflags="-s -w" -o $(GO_BIN) ./cmd/driftnet2

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
