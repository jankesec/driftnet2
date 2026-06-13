package sniffer

import (
	"fmt"
	"time"

	"github.com/byjanke/driftnet2/pkg/ebpf"
)

type xdpWrapper struct {
	xdp *ebpf.XDPSniffer
	ch  chan *RawPacket
}

func NewXDPLive(iface string) (*xdpWrapper, error) {
	xdp, err := ebpf.NewXDPSniffer(iface)
	if err != nil {
		return nil, fmt.Errorf("xdp: %w", err)
	}

	w := &xdpWrapper{
		xdp: xdp,
		ch:  make(chan *RawPacket, 256),
	}

	go func() {
		for evt := range xdp.Events() {
			w.ch <- &RawPacket{
				Timestamp: time.Now(),
				SrcIP:     evt.SrcIPString(),
				DstIP:     evt.DstIPString(),
				SrcPort:   evt.SrcPort,
				DstPort:   evt.DstPort,
				Protocol:  evt.Protocol,
				Payload:   evt.Data[:evt.PayloadLen],
			}
		}
		close(w.ch)
	}()

	return w, nil
}

func (w *xdpWrapper) Events() <-chan *RawPacket {
	return w.ch
}

func (w *xdpWrapper) Close() error {
	if w.xdp != nil {
		return w.xdp.Close()
	}
	return nil
}
