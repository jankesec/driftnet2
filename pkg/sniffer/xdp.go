package sniffer

import (
	"fmt"
	"sync"
	"time"

	"github.com/jankesec/driftnet2/pkg/ebpf"
)

type xdpWrapper struct {
	xdp       *ebpf.XDPSniffer
	ch        chan *RawPacket
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func NewXDPLive(iface, objPath string) (*xdpWrapper, error) {
	xdp, err := ebpf.NewXDPSniffer(iface, objPath)
	if err != nil {
		return nil, fmt.Errorf("xdp: %w", err)
	}

	w := &xdpWrapper{
		xdp:  xdp,
		ch:   make(chan *RawPacket, 256),
		done: make(chan struct{}),
	}

	go func() {
		defer close(w.ch)
		for evt := range xdp.Events() {
			pkt := rawPacketFromXDPEvent(evt)
			select {
			case w.ch <- pkt:
			case <-w.done:
				return
			}
		}
	}()

	return w, nil
}

func (w *xdpWrapper) Events() <-chan *RawPacket {
	return w.ch
}

func (w *xdpWrapper) Close() error {
	w.closeOnce.Do(func() {
		close(w.done)
		if w.xdp != nil {
			w.closeErr = w.xdp.Close()
		}
	})
	return w.closeErr
}

func rawPacketFromXDPEvent(evt *ebpf.PacketEvent) *RawPacket {
	payloadLen := min(int(evt.PayloadLen), len(evt.Data))
	return &RawPacket{
		Timestamp: time.Now(),
		SrcIP:     evt.SrcIPString(),
		DstIP:     evt.DstIPString(),
		SrcPort:   evt.SrcPort,
		DstPort:   evt.DstPort,
		Protocol:  evt.Protocol,
		Payload:   evt.Data[:payloadLen],
	}
}
