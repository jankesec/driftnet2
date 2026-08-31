// Command gen writes a small, reproducible sample PCAP exercising all nine
// protocol parsers with obviously-synthetic credentials. All addresses are RFC
// 5737 documentation ranges and all credentials are fake.
//
// Run: go run ./examples/gen [output.pcap]
package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/jankesec/driftnet2/pkg/sniffer"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// utf16le encodes an ASCII string as little-endian UTF-16 (as NTLM carries names).
func utf16le(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

// ntlmType3 builds a minimal NTLMSSP AUTHENTICATE (type 3) message carrying a
// domain and user in their security buffers (offsets 28 and 36).
func ntlmType3(domain, user string) []byte {
	d16, u16 := utf16le(domain), utf16le(user)
	const hdr = 64
	buf := make([]byte, hdr+len(d16)+len(u16))
	copy(buf, []byte("NTLMSSP\x00"))
	buf[8] = 3 // MessageType = 3
	domOff, usrOff := hdr, hdr+len(d16)
	binary.LittleEndian.PutUint16(buf[28:], uint16(len(d16)))
	binary.LittleEndian.PutUint16(buf[30:], uint16(len(d16)))
	binary.LittleEndian.PutUint32(buf[32:], uint32(domOff))
	binary.LittleEndian.PutUint16(buf[36:], uint16(len(u16)))
	binary.LittleEndian.PutUint16(buf[38:], uint16(len(u16)))
	binary.LittleEndian.PutUint32(buf[40:], uint32(usrOff))
	copy(buf[domOff:], d16)
	copy(buf[usrOff:], u16)
	return buf
}

// ldapBind builds a minimal LDAP simple-bind request (version 3).
func ldapBind(dn, password string) []byte {
	buf := []byte{0x30, 0x00, 0x02, 0x01, 0x01, 0x60, 0x00, 0x02, 0x01, 0x03, 0x04, byte(len(dn))}
	buf = append(buf, []byte(dn)...)
	buf = append(buf, 0x80, byte(len(password)))
	buf = append(buf, []byte(password)...)
	buf[1] = byte(len(buf) - 2)
	buf[6] = byte(len(buf) - 7)
	return buf
}

// dnsQuery builds a DNS query packet for qname (A/IN).
func dnsQuery(qname string) []byte {
	labels := strings.Split(qname, ".")
	buf := make([]byte, 12+len(qname)+2+4)
	buf[1] = 0x01 // ID
	buf[5] = 0x01 // QDCOUNT = 1
	off := 12
	for _, l := range labels {
		buf[off] = byte(len(l))
		off++
		copy(buf[off:], l)
		off += len(l)
	}
	off++             // zero-length root label
	buf[off+1] = 0x01 // QTYPE = A
	buf[off+3] = 0x01 // QCLASS = IN
	return buf
}

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

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	sessions := []struct {
		src, dst string
		sport    uint16
		dport    uint16
		proto    uint8 // 6=TCP, 17=UDP
		payload  []byte
	}{
		{"192.0.2.10", "198.51.100.20", 49001, 21, 6, []byte("USER demo\r\nPASS Password123\r\n")},
		{"192.0.2.11", "198.51.100.21", 49002, 80, 6, []byte("GET / HTTP/1.1\r\nHost: intranet.example\r\nAuthorization: Basic " + b64("demo:Password123") + "\r\n\r\n")},
		{"192.0.2.12", "198.51.100.22", 49003, 110, 6, []byte("USER demo@example.test\r\nPASS Password123\r\n")},
		{"192.0.2.13", "198.51.100.23", 49004, 143, 6, []byte("a001 LOGIN \"demo@example.test\" \"Password123\"\r\n")},
		{"192.0.2.14", "198.51.100.24", 49005, 587, 6, []byte("AUTH PLAIN " + b64("\x00postmaster\x00smtppass") + "\r\n")},
		{"192.0.2.15", "198.51.100.25", 49006, 23, 6, []byte("corp-router login: demo\r\n")},
		{"192.0.2.16", "198.51.100.26", 49007, 389, 6, ldapBind("cn=admin,dc=corp", "ldappass")},
		{"192.0.2.17", "198.51.100.27", 49008, 445, 6, ntlmType3("CORP", "jsmith")},
		{"192.0.2.18", "8.8.8.8", 49009, 53, 17, dnsQuery("TXlDMkV4ZmlsUGF5bG9hZERhdGFHb2VzSGVyZQ.c2.example.test")},
	}

	for i, s := range sessions {
		pkt := &sniffer.RawPacket{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			SrcIP:     s.src,
			DstIP:     s.dst,
			SrcPort:   s.sport,
			DstPort:   s.dport,
			Protocol:  s.proto,
			Payload:   s.payload,
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
