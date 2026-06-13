package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type PacketEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	Flags      uint8
	PayloadLen uint16
	_          [2]byte
	Data       [1480]byte
}

func (e PacketEvent) SrcIPString() string {
	return uint32ToIP(e.SrcIP).String()
}

func (e PacketEvent) DstIPString() string {
	return uint32ToIP(e.DstIP).String()
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
}

type XDPSniffer struct {
	iface   string
	objs    *xdpObjects
	link    link.Link
	reader  *ringbuf.Reader
	stopCh  chan struct{}
}

type xdpObjects struct {
	Program *ebpf.Program `ebpf:"xdp_sniff"`
	Packets *ebpf.Map     `ebpf:"packets"`
}

func NewXDPSniffer(iface string) (*XDPSniffer, error) {
	if _, err := os.Stat("bpf/xdp_sniff.o"); os.IsNotExist(err) {
		return nil, fmt.Errorf("bpf/xdp_sniff.o not found — run 'make bpf' first")
	}

	spec, err := ebpf.LoadCollectionSpec("bpf/xdp_sniff.o")
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	var objs xdpObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load & assign: %w", err)
	}

	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		objs.Program.Close()
		objs.Packets.Close()
		return nil, fmt.Errorf("get interface %s: %w", iface, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Program,
		Interface: netIface.Index,
	})
	if err != nil {
		objs.Program.Close()
		objs.Packets.Close()
		return nil, fmt.Errorf("attach XDP: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Packets)
	if err != nil {
		l.Close()
		objs.Program.Close()
		objs.Packets.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &XDPSniffer{
		iface:  iface,
		objs:   &objs,
		link:   l,
		reader: rd,
		stopCh: make(chan struct{}),
	}, nil
}

func (x *XDPSniffer) Read() (*PacketEvent, error) {
	record, err := x.reader.Read()
	if err != nil {
		return nil, err
	}

	var evt PacketEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
		return nil, fmt.Errorf("decode event: %w", err)
	}

	return &evt, nil
}

func (x *XDPSniffer) Events() <-chan *PacketEvent {
	ch := make(chan *PacketEvent, 256)
	go func() {
		defer close(ch)
		for {
			select {
			case <-x.stopCh:
				return
			default:
				evt, err := x.Read()
				if err != nil {
					return
				}
				ch <- evt
			}
		}
	}()
	return ch
}

func (x *XDPSniffer) Close() error {
	close(x.stopCh)
	if x.reader != nil {
		x.reader.Close()
	}
	if x.link != nil {
		x.link.Close()
	}
	if x.objs != nil {
		x.objs.Program.Close()
		x.objs.Packets.Close()
	}
	return nil
}

