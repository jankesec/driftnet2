package sniffer

import (
	"testing"

	"github.com/jankesec/driftnet2/pkg/ebpf"
)

func TestRawPacketFromXDPEventBoundsPayloadLength(t *testing.T) {
	evt := &ebpf.PacketEvent{PayloadLen: 65535}
	pkt := rawPacketFromXDPEvent(evt)
	if got, want := len(pkt.Payload), len(evt.Data); got != want {
		t.Fatalf("payload length = %d, want bounded length %d", got, want)
	}
}
