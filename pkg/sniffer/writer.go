package sniffer

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/google/gopacket/layers"
)

type PCAPWriter struct {
	f        *os.File
	linkType layers.LinkType
	mu       sync.Mutex
}

func NewPCAPWriter(filename string, linkType layers.LinkType) (*PCAPWriter, error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("create pcap: %w", err)
	}

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[8:], 0)
	binary.LittleEndian.PutUint32(hdr[12:], 0)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], uint32(linkType))

	if _, err := f.Write(hdr); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write pcap header: %w", err)
	}

	return &PCAPWriter{f: f, linkType: linkType}, nil
}

func (w *PCAPWriter) WritePacket(pkt *RawPacket) error {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil
	}

	var data []byte
	if len(pkt.FullData) > 0 {
		data = pkt.FullData
	} else {
		data = reconstructPacket(pkt)
	}
	if len(data) == 0 {
		return nil
	}

	ts := pkt.Timestamp
	if ts.IsZero() {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	recHdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(recHdr[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(recHdr[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(recHdr[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(recHdr[12:], uint32(len(data)))

	if _, err := w.f.Write(recHdr); err != nil {
		return err
	}
	_, err := w.f.Write(data)
	return err
}

func reconstructPacket(pkt *RawPacket) []byte {
	srcIP := net.ParseIP(pkt.SrcIP)
	dstIP := net.ParseIP(pkt.DstIP)
	if srcIP == nil || dstIP == nil {
		return nil
	}

	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	isIPv4 := src4 != nil && dst4 != nil

	if isIPv4 {
		return buildIPv4Packet(src4, dst4, pkt)
	}
	src6 := srcIP.To16()
	dst6 := dstIP.To16()
	if src6 != nil && dst6 != nil {
		return buildIPv6Packet(src6, dst6, pkt)
	}
	return nil
}

func buildIPv4Packet(src, dst net.IP, pkt *RawPacket) []byte {
	payloadLen := len(pkt.Payload)
	transportHdrLen := 8
	if pkt.Protocol == 6 {
		transportHdrLen = 20
	}
	totalLen := 20 + transportHdrLen + payloadLen
	buf := make([]byte, totalLen)

	buf[0] = 0x45
	buf[1] = 0x00
	binary.BigEndian.PutUint16(buf[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:], 0)
	buf[6] = 0x40
	buf[7] = 0x00
	buf[8] = 64
	buf[9] = pkt.Protocol
	binary.BigEndian.PutUint16(buf[10:], 0)
	copy(buf[12:16], src)
	copy(buf[16:20], dst)

	off := 20
	if pkt.Protocol == 6 {
		binary.BigEndian.PutUint16(buf[off:], pkt.SrcPort)
		binary.BigEndian.PutUint16(buf[off+2:], pkt.DstPort)
		binary.BigEndian.PutUint32(buf[off+4:], 0)
		binary.BigEndian.PutUint32(buf[off+8:], 0)
		buf[off+12] = 0x50
		buf[off+13] = 0x10
		binary.BigEndian.PutUint16(buf[off+14:], 65535)
		binary.BigEndian.PutUint16(buf[off+16:], 0)
		binary.BigEndian.PutUint16(buf[off+18:], 0)
		off += 20
	} else {
		binary.BigEndian.PutUint16(buf[off:], pkt.SrcPort)
		binary.BigEndian.PutUint16(buf[off+2:], pkt.DstPort)
		binary.BigEndian.PutUint16(buf[off+4:], uint16(8+payloadLen))
		binary.BigEndian.PutUint16(buf[off+6:], 0)
		off += 8
	}

	copy(buf[off:], pkt.Payload)
	return buf
}

func buildIPv6Packet(src, dst net.IP, pkt *RawPacket) []byte {
	payloadLen := len(pkt.Payload)
	transportHdrLen := 8
	if pkt.Protocol == 6 {
		transportHdrLen = 20
	}
	totalLen := 40 + transportHdrLen + payloadLen
	buf := make([]byte, totalLen)

	buf[0] = 0x60
	buf[1] = 0x00
	buf[2] = 0x00
	buf[3] = 0x00
	binary.BigEndian.PutUint16(buf[4:], uint16(transportHdrLen+payloadLen))
	buf[6] = pkt.Protocol
	buf[7] = 64
	copy(buf[8:24], src)
	copy(buf[24:40], dst)

	off := 40
	if pkt.Protocol == 6 {
		binary.BigEndian.PutUint16(buf[off:], pkt.SrcPort)
		binary.BigEndian.PutUint16(buf[off+2:], pkt.DstPort)
		binary.BigEndian.PutUint32(buf[off+4:], 0)
		binary.BigEndian.PutUint32(buf[off+8:], 0)
		buf[off+12] = 0x50
		buf[off+13] = 0x10
		binary.BigEndian.PutUint16(buf[off+14:], 65535)
		binary.BigEndian.PutUint16(buf[off+16:], 0)
		binary.BigEndian.PutUint16(buf[off+18:], 0)
		off += 20
	} else {
		binary.BigEndian.PutUint16(buf[off:], pkt.SrcPort)
		binary.BigEndian.PutUint16(buf[off+2:], pkt.DstPort)
		binary.BigEndian.PutUint16(buf[off+4:], uint16(8+payloadLen))
		binary.BigEndian.PutUint16(buf[off+6:], 0)
		off += 8
	}

	copy(buf[off:], pkt.Payload)
	return buf
}

func (w *PCAPWriter) Close() error {
	if w.f != nil {
		return w.f.Close()
	}
	return nil
}
