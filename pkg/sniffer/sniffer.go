package sniffer

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type AFPacketSniffer struct {
	handle   *pcap.Handle
	linkType layers.LinkType
	stopCh   chan struct{}
}

type RawPacket struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Payload   []byte
	FullData  []byte
}

func (s *AFPacketSniffer) LinkType() layers.LinkType {
	return s.linkType
}

func NewAFPacketSniffer(iface string) (*AFPacketSniffer, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open: %w", err)
	}

	filter := "tcp or udp"
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("bpf filter: %w", err)
	}

	return &AFPacketSniffer{
		handle:   handle,
		linkType: handle.LinkType(),
		stopCh:   make(chan struct{}),
	}, nil
}

func NewPCAPSniffer(filename string) (*AFPacketSniffer, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("pcap offline: %w", err)
	}

	return &AFPacketSniffer{
		handle:   handle,
		linkType: handle.LinkType(),
		stopCh:   make(chan struct{}),
	}, nil
}

func (s *AFPacketSniffer) Events() <-chan *RawPacket {
	ch := make(chan *RawPacket, 256)
	ps := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	go func() {
		defer close(ch)
		for {
			select {
			case <-s.stopCh:
				return
			case pkt := <-ps.Packets():
				if pkt == nil {
					return
				}
				rp := convertPacket(pkt)
				if rp != nil {
					ch <- rp
				}
			}
		}
	}()
	return ch
}

func (s *AFPacketSniffer) Close() error {
	close(s.stopCh)
	if s.handle != nil {
		s.handle.Close()
	}
	return nil
}

func convertPacket(pkt gopacket.Packet) *RawPacket {
	var srcIP, dstIP string

	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		srcIP = ip6.SrcIP.String()
		dstIP = ip6.DstIP.String()
	} else {
		return nil
	}

	rp := &RawPacket{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		FullData:  pkt.Data(),
	}

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		rp.SrcPort = uint16(tcp.SrcPort)
		rp.DstPort = uint16(tcp.DstPort)
		rp.Protocol = 6
		rp.Payload = tcp.Payload
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		rp.SrcPort = uint16(udp.SrcPort)
		rp.DstPort = uint16(udp.DstPort)
		rp.Protocol = 17
		rp.Payload = udp.Payload
	} else {
		return nil
	}

	return rp
}

func IsInterfaceValid(iface string) bool {
	_, err := net.InterfaceByName(iface)
	return err == nil
}

func LinkTypeFromSniffer(sniff interface{}) layers.LinkType {
	if s, ok := sniff.(*AFPacketSniffer); ok {
		return s.LinkType()
	}
	return layers.LinkTypeRaw
}
