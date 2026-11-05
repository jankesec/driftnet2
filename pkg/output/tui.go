package output

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jankesec/driftnet2/internal/buildinfo"
	"github.com/jankesec/driftnet2/pkg/protocol"
)

type TerminalUI struct {
	creds     []protocol.Credential
	credCount int
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
	t.credCount++
}

func (t *TerminalUI) PrintHeader() {
	bar := strings.Repeat("─", 80)
	fmt.Printf("┌%s┐\n", bar)
	fmt.Printf("│ driftnet2 %-8s │  %-6s  │  %-9s │  %-35s │\n",
		buildinfo.Version, t.iface, t.mode, time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("├%s┤\n", bar)
}

func (t *TerminalUI) PrintFooter() {
	bar := strings.Repeat("─", 80)
	sessions := 0
	tunnels := 0
	hashes := 0
	passwords := 0
	for _, c := range t.creds {
		switch {
		case c.Token != "":
			sessions++
		case c.DNSQuery != "":
			tunnels++
		case c.Hash != "":
			hashes++
		case c.Password != "":
			passwords++
		}
	}
	fmt.Printf("├%s┤\n", bar)
	elapsed := time.Since(t.startTime).Round(time.Second)
	fmt.Printf("│ Total: %-3d │ Passwords: %-2d │ Hashes: %-2d │ Sessions: %-2d │ %-9s │\n",
		len(t.creds), passwords, hashes, sessions, elapsed)
	if tunnels > 0 {
		fmt.Printf("│ DNS Tunnels: %-67d│\n", tunnels)
	}
	fmt.Printf("└%s┘\n", bar)
}

func (t *TerminalUI) PrintCredential(c protocol.Credential) {
	ts := c.Timestamp.Format("15:04:05")
	proto := fmt.Sprintf("%-6s", c.Protocol)
	src := fmt.Sprintf("%-39s", c.SrcIP)
	dst := c.DstIP
	if c.DstPort > 0 {
		dst = net.JoinHostPort(dst, strconv.Itoa(int(c.DstPort)))
	}

	fmt.Printf("│ %s %s %s → %s │\n", ts, proto, src, dst)

	value := c.SafeString()
	if len(value) > 64 {
		value = value[:64] + "..."
	}
	if value != "" {
		fmt.Printf("│   %s  %s\n", c.Emoji(), value)
	}
}

func (t *TerminalUI) GetCredentials() []protocol.Credential {
	return t.creds
}
