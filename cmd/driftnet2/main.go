package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/jankesec/driftnet2/pkg/output"
	"github.com/jankesec/driftnet2/pkg/protocol"
	"github.com/jankesec/driftnet2/pkg/sniffer"
)

const banner = `
   ____       _  __  __ _      _     ____
  |  _ \ _ __(_)/ _|/ _| |_ _ | |_  |___ \
  | | | | '__| | |_| |_| __/ _ \| __|   __) |
  | |_| | |  | |  _|  _| || (_) | |_   / __/
  |____/|_|  |_|_| |_|  \__\___/ \__| |_____|

    kernel-level packet sniffer & credential extractor
`

func main() {
	iface := flag.String("iface", "", "network interface (e.g. eth0, en0)")
	jsonOut := flag.String("output", "", "JSON output file")
	protocols := flag.String("proto", "http,dns,smb,ldap,ftp,telnet,pop3,imap,smtp", "protocols to sniff")
	pcapRead := flag.String("pcap", "", "read from PCAP file (offline mode)")
	pcapWrite := flag.String("w", "", "write captured packets to PCAP file")
	verbose := flag.Bool("v", false, "verbose output (show all protocol events)")
	bpfPath := flag.String("bpf", "", "path to compiled eBPF object (default: auto-detect)")
	flag.Parse()

	fmt.Print(banner)

	protoSet := parseProtoSet(*protocols)

	if *pcapRead != "" {
		runOffline(*pcapRead, protoSet, *jsonOut, *verbose)
		return
	}

	if *iface == "" {
		fmt.Println("usage: driftnet2 -iface <interface> [flags]")
		fmt.Println("\nflags:")
		flag.PrintDefaults()
		fmt.Println("\nexamples:")
		fmt.Println("  driftnet2 -iface eth0")
		fmt.Println("  driftnet2 -iface en0 --proto http,ftp")
		fmt.Println("  driftnet2 -iface eth0 -output creds.json")
		fmt.Println("  driftnet2 -iface eth0 -w capture.pcap")
		fmt.Println("  driftnet2 -pcap capture.pcap --proto http,dns")
		os.Exit(1)
	}

	if !sniffer.IsInterfaceValid(*iface) {
		log.Fatalf("interface %s not found", *iface)
	}

	mode := "AF_PACKET"
	hasXDP := false
	bpfObj := ""
	if runtime.GOOS == "linux" {
		if p, ok := resolveBPFObject(*bpfPath); ok {
			mode = "XDP"
			hasXDP = true
			bpfObj = p
		}
	}

	fmt.Printf("[*] interface: %-8s  mode: %-10s  proto: %s\n", *iface, mode, *protocols)
	if *pcapWrite != "" {
		fmt.Printf("[*] pcap write: %s\n", *pcapWrite)
	}
	fmt.Println()

	var sniff interface {
		Events() <-chan *sniffer.RawPacket
		Close() error
	}

	var err error
	if hasXDP {
		sniff, err = sniffer.NewXDPLive(*iface, bpfObj)
		if err != nil {
			log.Printf("XDP failed: %v — falling back to AF_PACKET", err)
			hasXDP = false
			mode = "AF_PACKET"
			sniff, err = sniffer.NewAFPacketSniffer(*iface)
		}
	}
	if !hasXDP {
		sniff, err = sniffer.NewAFPacketSniffer(*iface)
	}
	if err != nil {
		log.Fatalf("sniffer: %v", err)
	}
	defer func() { _ = sniff.Close() }()

	var pcapW *sniffer.PCAPWriter
	if *pcapWrite != "" {
		linkType := sniffer.LinkTypeFromSniffer(sniff)
		pcapW, err = sniffer.NewPCAPWriter(*pcapWrite, linkType)
		if err != nil {
			log.Fatalf("pcap writer: %v", err)
		}
		defer func() { _ = pcapW.Close() }()
	}

	tui := output.NewTerminalUI(*iface, mode)

	var mu sync.Mutex
	var allCreds []protocol.Credential
	seen := make(map[string]bool)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	tui.PrintHeader()

	go func() {
		for pkt := range sniff.Events() {
			if pcapW != nil {
				if err := pcapW.WritePacket(pkt); err != nil {
					log.Printf("pcap write: %v", err)
				}
			}

			if len(pkt.Payload) == 0 {
				continue
			}

			creds := dispatchProtocol(pkt, protoSet)
			for _, c := range creds {
				key := dedupKey(c)
				mu.Lock()
				if seen[key] {
					mu.Unlock()
					continue
				}
				seen[key] = true
				allCreds = append(allCreds, c)
				mu.Unlock()

				tui.AddCredential(c)
				tui.PrintCredential(c)
			}
		}
	}()

	<-sigCh
	tui.PrintFooter()
	fmt.Println("\n[*] shutting down...")

	mu.Lock()
	finalCreds := make([]protocol.Credential, len(allCreds))
	copy(finalCreds, allCreds)
	mu.Unlock()

	if *jsonOut != "" {
		if err := output.WriteJSON(finalCreds, *jsonOut); err != nil {
			log.Printf("json: %v", err)
		}
		fmt.Printf("[*] saved %d credentials → %s\n", len(finalCreds), *jsonOut)
	}
}

func runOffline(filename string, protoSet map[string]bool, jsonOut string, verbose bool) {
	fmt.Printf("[*] offline mode: %s\n", filename)

	s, err := sniffer.NewPCAPSniffer(filename)
	if err != nil {
		log.Fatalf("pcap: %v", err)
	}
	defer func() { _ = s.Close() }()

	var allCreds []protocol.Credential
	seen := make(map[string]bool)
	pktCount := 0

	for pkt := range s.Events() {
		pktCount++
		if len(pkt.Payload) == 0 {
			continue
		}
		creds := dispatchProtocol(pkt, protoSet)
		for _, c := range creds {
			key := dedupKey(c)
			if seen[key] {
				continue
			}
			seen[key] = true
			allCreds = append(allCreds, c)
			fmt.Printf("[%s] %s %s:%s → %s\n", c.Protocol, c.Type, c.SrcIP, c.DstIP, c.String())
		}
		if verbose && len(creds) == 0 {
			fmt.Printf("[pkt %d] %s:%d → %s:%d proto=%d len=%d\n",
				pktCount, pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Protocol, len(pkt.Payload))
		}
	}

	fmt.Printf("\n[*] %d packets processed, %d unique credentials found in %s\n", pktCount, len(allCreds), filename)

	if jsonOut != "" {
		if err := output.WriteJSON(allCreds, jsonOut); err != nil {
			log.Printf("json: %v", err)
		}
		fmt.Printf("[*] saved → %s\n", jsonOut)
	}
}

func dispatchProtocol(pkt *sniffer.RawPacket, protoSet map[string]bool) []protocol.Credential {
	srcPort := pkt.SrcPort
	dstPort := pkt.DstPort

	switch {
	case (dstPort == 53 || srcPort == 53) && protoSet["dns"]:
		return protocol.ParseDNS(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)

	case (dstPort == 445 || srcPort == 445) && protoSet["smb"]:
		return protocol.ParseSMB(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)

	case (dstPort == 389 || srcPort == 389) && protoSet["ldap"]:
		return protocol.ParseLDAP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)

	case (dstPort == 21 || srcPort == 21) && protoSet["ftp"]:
		return protocol.ParseFTP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)

	case (dstPort == 23 || srcPort == 23) && protoSet["telnet"]:
		return protocol.ParseTelnet(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)

	case (dstPort == 110 || srcPort == 110) && protoSet["pop3"]:
		return protocol.ParsePOP3(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)

	case (dstPort == 143 || srcPort == 143) && protoSet["imap"]:
		return protocol.ParseIMAP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)

	case (dstPort == 25 || srcPort == 25 || dstPort == 587 || srcPort == 587) && protoSet["smtp"]:
		return protocol.ParseSMTP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)

	case protoSet["http"]:
		return protocol.ParseHTTP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
	}
	return nil
}

func dedupKey(c protocol.Credential) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		c.Protocol, c.Type, c.SrcIP, c.DstIP,
		c.Username, c.Password, c.Token, c.Hash, c.DNSQuery)
}

func parseProtoSet(protoStr string) map[string]bool {
	s := make(map[string]bool)
	for _, p := range strings.Split(protoStr, ",") {
		s[strings.TrimSpace(strings.ToLower(p))] = true
	}
	return s
}

// resolveBPFObject locates the compiled XDP object independent of the current
// working directory. Order: explicit flag, DRIFTNET2_BPF env, next to the
// executable, then ./bpf/xdp_sniff.o as a last resort.
func resolveBPFObject(flagPath string) (string, bool) {
	var candidates []string
	if flagPath != "" {
		candidates = append(candidates, flagPath)
	}
	if env := os.Getenv("DRIFTNET2_BPF"); env != "" {
		candidates = append(candidates, env)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "bpf", "xdp_sniff.o"))
	}
	candidates = append(candidates, filepath.Join("bpf", "xdp_sniff.o"))
	for _, c := range candidates {
		// #nosec G703 -- candidate paths are operator-provided (flag/env); local CLI tool
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, true
		}
	}
	return "", false
}
