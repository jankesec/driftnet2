package sniffer

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"
)

type PCAPWriter struct {
	f  *os.File
	mu sync.Mutex
}

func NewPCAPWriter(filename string) (*PCAPWriter, error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("create pcap: %w", err)
	}

	// PCAP global header
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(hdr[4:], 2)           // version major
	binary.LittleEndian.PutUint16(hdr[6:], 4)           // version minor
	binary.LittleEndian.PutUint32(hdr[8:], 0)           // timezone
	binary.LittleEndian.PutUint32(hdr[12:], 0)          // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:], 65535)       // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], 228)         // LINKTYPE_RAW (raw IPv4/IPv6)

	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return nil, fmt.Errorf("write pcap header: %w", err)
	}

	return &PCAPWriter{f: f}, nil
}

func (w *PCAPWriter) WritePacket(pkt *RawPacket) error {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil
	}

	now := time.Now()

	w.mu.Lock()
	defer w.mu.Unlock()

	// PCAP record header (16 bytes)
	recHdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(recHdr[0:], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(recHdr[4:], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(recHdr[8:], uint32(len(pkt.Payload)))
	binary.LittleEndian.PutUint32(recHdr[12:], uint32(len(pkt.Payload)))

	if _, err := w.f.Write(recHdr); err != nil {
		return err
	}
	_, err := w.f.Write(pkt.Payload)
	return err
}

func (w *PCAPWriter) Close() error {
	if w.f != nil {
		return w.f.Close()
	}
	return nil
}
