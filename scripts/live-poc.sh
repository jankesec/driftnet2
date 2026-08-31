#!/usr/bin/env bash
#
# live-poc.sh — runtime proof-of-concept for driftnet2 on a Linux host.
#
# CI only *compiles* the eBPF object and runs unit tests; it never captures live
# traffic. This script proves the two runtime capture paths by sniffing the
# loopback interface while a fake cleartext FTP login is sent to 127.0.0.1:21:
#
#   1. AF_PACKET (userspace/libpcap) — no eBPF object present
#   2. eBPF/XDP  (kernel)            — with the compiled object (auto-detected)
#
# Everything is synthetic (creds "demo:Password123", loopback only). It is NOT
# run by CI and cannot run on macOS.
#
# Requirements: Linux · root (sudo) · Go 1.24+ · clang/llvm · python3
# Usage:        sudo ./scripts/live-poc.sh
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "error: $*" >&2; exit 1; }
[ "$(uname -s)" = "Linux" ] || fail "Linux only (this validates the kernel/XDP path)"
[ "$(id -u)" -eq 0 ] || fail "run as root: sudo $0"
for t in go clang python3; do command -v "$t" >/dev/null 2>&1 || fail "missing tool: $t"; done

echo "[*] building binary..."
make clean >/dev/null 2>&1 || true
go build -o driftnet2 ./cmd/driftnet2

# Send a synthetic cleartext FTP login over loopback:21 (self-contained, no nc).
generate_traffic() {
  python3 - <<'PY'
import socket, threading, time
def server():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 21)); s.listen(1)
    try:
        c, _ = s.accept(); c.recv(256); c.close()
    finally:
        s.close()
threading.Thread(target=server, daemon=True).start(); time.sleep(0.5)
c = socket.create_connection(("127.0.0.1", 21))
c.sendall(b"USER demo\r\nPASS Password123\r\n"); time.sleep(0.5); c.close()
PY
}

run_capture() { # $1 = human label
  local label="$1" out log mode
  out="$(mktemp)"; log="$(mktemp)"
  echo; echo "=== PoC: $label ==="
  ./driftnet2 -iface lo --proto ftp -output "$out" >"$log" 2>&1 &
  local pid=$!
  sleep 2                       # let the sniffer attach
  generate_traffic || true
  sleep 2
  kill -INT "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  mode="$(grep -o 'mode: [A-Z_]*' "$log" | head -1 || true)"
  echo "  ${mode:-mode: ?}"
  if grep -q 'Password123' "$out" 2>/dev/null; then
    echo "  ✓ captured a cleartext FTP credential (demo:Password123)"
  else
    echo "  ✗ nothing captured — sniffer log:"; sed 's/^/      /' "$log" | head -8
  fi
  rm -f "$out" "$log"
}

# 1) AF_PACKET — no eBPF object on disk, so XDP is not auto-detected.
run_capture "AF_PACKET (userspace / libpcap)"

# 2) eBPF/XDP — compile the object; the binary auto-detects ./bpf/xdp_sniff.o.
echo; echo "[*] compiling eBPF/XDP object..."
make bpf
run_capture "eBPF/XDP (kernel; falls back to AF_PACKET if attach is refused)"

echo; echo "[*] done. Note: XDP on 'lo' uses generic mode and needs kernel 5.8+."
