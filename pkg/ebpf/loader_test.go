package ebpf

import "testing"

func TestXDPSnifferCloseIsIdempotent(t *testing.T) {
	x := &XDPSniffer{stopCh: make(chan struct{})}
	if err := x.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := x.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
