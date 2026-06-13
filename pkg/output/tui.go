package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/byjanke/driftnet2/pkg/protocol"
)

type TerminalUI struct {
	creds     []protocol.Credential
	pktCount  int
	startTime time.Time
	iface     string
	mode      string
}

func NewTerminalUI(iface, mode string) *TerminalUI {
	return &TerminalUI{
		startTime: time.Now(),
		iface:     iface,
		mode:      mode,
	}
}

func (t *TerminalUI) AddCredential(c protocol.Credential) {
	t.creds = append(t.creds, c)
	t.pktCount++
}

func (t *TerminalUI) PrintHeader() {
	bar := strings.Repeat("─", 57)
	fmt.Printf("┌%s┐\n", bar)
	fmt.Printf("│ driftnet2 v1.0  │  %-6s  │  %-4s  │  pkts: %-6d│\n",
		t.iface, t.mode, t.pktCount)
	fmt.Printf("├%s┤\n", bar)
}

func (t *TerminalUI) PrintFooter() {
	bar := strings.Repeat("─", 57)
	sessions := 0
	tunnels := 0
	for _, c := range t.creds {
		if c.Token != "" {
			sessions++
		}
		if c.DNSQuery != "" {
			tunnels++
		}
	}
	fmt.Printf("├%s┤\n", bar)
	elapsed := time.Since(t.startTime).Round(time.Second)
	fmt.Printf("│ Credentials: %-2d │ Sessions: %-2d │ Tunnels: %-2d │ %-8s │\n",
		len(t.creds), sessions, tunnels, elapsed)
	fmt.Printf("└%s┘\n", bar)
}

func (t *TerminalUI) PrintCredential(c protocol.Credential) {
	timestamp := time.Now().Format("15:04:05")
	protocol := fmt.Sprintf("%-5s", c.Protocol)
	srcIP := fmt.Sprintf("%-15s", c.SrcIP)
	dstInfo := fmt.Sprintf("%s:%d", c.DstIP, c.DstPort)

	if c.Password != "" {
		fmt.Printf("│ %s %s %s → %-21s │\n", timestamp, protocol, srcIP, dstInfo)
		fmt.Printf("│   %s  %s:%-24s │\n", c.Emoji(), c.Username, c.Password)
	} else if c.Token != "" {
		fmt.Printf("│ %s %s %s → %-21s │\n", timestamp, protocol, srcIP, dstInfo)
		fmt.Printf("│   %s %-39s │\n", c.Emoji(), c.Token)
	} else if c.Hash != "" {
		fmt.Printf("│ %s %s %s → %-21s │\n", timestamp, protocol, srcIP, dstInfo)
		fmt.Printf("│   %s %-39s │\n", c.Emoji(), c.Hash)
	} else if c.DNSQuery != "" {
		fmt.Printf("│ %s %s %s → %-21s │\n", timestamp, protocol, srcIP, dstInfo)
		fmt.Printf("│   %s TUNNEL: %-33s │\n", c.Emoji(), c.DNSQuery)
	} else if c.Raw != "" {
		fmt.Printf("│ %s %s %s → %-21s │\n", timestamp, protocol, srcIP, dstInfo)
		fmt.Printf("│   %s %-39s │\n", "📎", c.Raw)
	}
}

func (t *TerminalUI) GetCredentials() []protocol.Credential {
	return t.creds
}
