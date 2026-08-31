// Command gen writes a small, reproducible sample PCAP containing
// obviously-synthetic cleartext credentials, used by the README demo.
//
// All addresses are RFC 5737 documentation ranges and all credentials are
// fake. Run: go run ./examples/gen [output.pcap]
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/jankesec/driftnet2/pkg/sniffer"
)

func main() {
	out := "examples/demo.pcap"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	w, err := sniffer.NewPCAPWriter(out, layers.LinkTypeRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "writer:", err)
		os.Exit(1)
	}

	basic := base64.StdEncoding.EncodeToString([]byte("demo:Password123"))
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	sessions := []struct {
		src, dst string
		sport    uint16
		dport    uint16
		payload  string
	}{
		{"192.0.2.10", "198.51.100.20", 49001, 21, "USER demo\r\nPASS Password123\r\n"},
		{"192.0.2.11", "198.51.100.21", 49002, 80, "GET / HTTP/1.1\r\nHost: intranet.example\r\nAuthorization: Basic " + basic + "\r\n\r\n"},
		{"192.0.2.12", "198.51.100.22", 49003, 110, "USER demo@example.test\r\nPASS Password123\r\n"},
		{"192.0.2.13", "198.51.100.23", 49004, 23, "corp-router login: demo\r\n"},
	}

	for i, s := range sessions {
		pkt := &sniffer.RawPacket{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			SrcIP:     s.src,
			DstIP:     s.dst,
			SrcPort:   s.sport,
			DstPort:   s.dport,
			Protocol:  6, // TCP
			Payload:   []byte(s.payload),
		}
		if err := w.WritePacket(pkt); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
	}

	if err := w.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "close:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d synthetic sessions to %s\n", len(sessions), out)
}
