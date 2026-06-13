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
	bar := strings.Repeat("─", 65)
	fmt.Printf("┌%s┐\n", bar)
	fmt.Printf("│ driftnet2 v2.0  │  %-6s  │  %-4s  │  %-24s  │\n",
		t.iface, t.mode, time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("├%s┤\n", bar)
}

func (t *TerminalUI) PrintFooter() {
	bar := strings.Repeat("─", 65)
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
	fmt.Printf("│ Total: %-3d │ Passwords: %-2d │ Hashes: %-2d │ Sessions: %-2d │ %-7s │\n",
		len(t.creds), passwords, hashes, sessions, elapsed)
	if tunnels > 0 {
		fmt.Printf("│ DNS Tunnels: %-52d│\n", tunnels)
	}
	fmt.Printf("└%s┘\n", bar)
}

func (t *TerminalUI) PrintCredential(c protocol.Credential) {
	ts := c.Timestamp.Format("15:04:05")
	proto := fmt.Sprintf("%-6s", c.Protocol)
	src := fmt.Sprintf("%-15s", c.SrcIP)
	dst := fmt.Sprintf("%s:%d", c.DstIP, c.DstPort)

	fmt.Printf("│ %s %s %s → %-21s │\n", ts, proto, src, dst)

	switch {
	case c.Password != "":
		fmt.Printf("│   %s  %s : %s\n", c.Emoji(), c.Username, c.Password)
	case c.Token != "":
		token := c.Token
		if len(token) > 50 {
			token = token[:50] + "..."
		}
		fmt.Printf("│   %s  %s\n", c.Emoji(), token)
	case c.Hash != "":
		hash := c.Hash
		if len(hash) > 50 {
			hash = hash[:50] + "..."
		}
		if c.Username != "" {
			fmt.Printf("│   %s  %s  %s\n", c.Emoji(), c.Username, hash)
		} else {
			fmt.Printf("│   %s  %s\n", c.Emoji(), hash)
		}
	case c.DNSQuery != "":
		query := c.DNSQuery
		if len(query) > 50 {
			query = query[:50] + "..."
		}
		fmt.Printf("│   %s  TUNNEL: %s\n", c.Emoji(), query)
	case c.Raw != "":
		raw := c.Raw
		if len(raw) > 50 {
			raw = raw[:50] + "..."
		}
		fmt.Printf("│   %s  %s\n", c.Emoji(), raw)
	}
}

func (t *TerminalUI) GetCredentials() []protocol.Credential {
	return t.creds
}
