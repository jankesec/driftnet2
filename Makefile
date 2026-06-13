.PHONY: all bpf build clean

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
