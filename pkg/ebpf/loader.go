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
	SrcIP      [16]byte
	DstIP      [16]byte
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	Flags      uint8
	PayloadLen uint16
	_          [2]byte
	Data       [1458]byte
}

func (e PacketEvent) SrcIPString() string {
	return ip16ToString(e.SrcIP)
}

func (e PacketEvent) DstIPString() string {
	return ip16ToString(e.DstIP)
}

func ip16ToString(b [16]byte) string {
	if isIPv4(b) {
		return net.IPv4(b[12], b[13], b[14], b[15]).String()
	}
	return net.IP(b[:]).String()
}

func isIPv4(b [16]byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0 && b[11] == 0
}

type XDPSniffer struct {
	iface  string
	objs   *xdpObjects
	link   link.Link
	reader *ringbuf.Reader
	stopCh chan struct{}
}

type xdpObjects struct {
	Program *ebpf.Program `ebpf:"xdp_sniff"`
	Packets *ebpf.Map     `ebpf:"packets"`
}

func NewXDPSniffer(iface, objPath string) (*XDPSniffer, error) {
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%s not found — run 'make bpf' first", objPath)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	var objs xdpObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load & assign: %w", err)
	}

	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		_ = objs.Program.Close()
		_ = objs.Packets.Close()
		return nil, fmt.Errorf("get interface %s: %w", iface, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Program,
		Interface: netIface.Index,
	})
	if err != nil {
		_ = objs.Program.Close()
		_ = objs.Packets.Close()
		return nil, fmt.Errorf("attach XDP: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Packets)
	if err != nil {
		_ = l.Close()
		_ = objs.Program.Close()
		_ = objs.Packets.Close()
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
		_ = x.reader.Close()
	}
	if x.link != nil {
		_ = x.link.Close()
	}
	if x.objs != nil {
		_ = x.objs.Program.Close()
		_ = x.objs.Packets.Close()
	}
	return nil
}
