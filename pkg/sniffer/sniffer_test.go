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
