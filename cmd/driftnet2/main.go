package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/byjanke/driftnet2/pkg/output"
	"github.com/byjanke/driftnet2/pkg/protocol"
	"github.com/byjanke/driftnet2/pkg/sniffer"
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
	protocols := flag.String("proto", "http,dns,smb,ldap", "protocols to sniff")
	pcapRead := flag.String("pcap", "", "read from PCAP file (offline mode)")
	flag.Parse()

	fmt.Print(banner)

	protoSet := parseProtoSet(*protocols)

	if *pcapRead != "" {
		runOffline(*pcapRead, protoSet, *jsonOut)
		return
	}

	if *iface == "" {
		fmt.Println("usage: driftnet2 -iface <interface> [flags]")
		fmt.Println("\nflags:")
		flag.PrintDefaults()
		fmt.Println("\nexamples:")
		fmt.Println("  driftnet2 -iface eth0")
		fmt.Println("  driftnet2 -iface en0 --proto http")
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
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("bpf/xdp_sniff.o"); err == nil {
			mode = "XDP"
			hasXDP = true
		}
	}

	fmt.Printf("[*] interface: %-8s  mode: %-10s  proto: %s\n\n", *iface, mode, *protocols)

	var s interface {
		Events() <-chan *sniffer.RawPacket
		Close() error
	}

	var err error
	if hasXDP {
		s, err = sniffer.NewXDPLive(*iface)
		if err != nil {
			log.Printf("XDP failed: %v — falling back to AF_PACKET", err)
			hasXDP = false
			mode = "AF_PACKET"
			s, err = sniffer.NewAFPacketSniffer(*iface)
		}
	}
	if !hasXDP {
		s, err = sniffer.NewAFPacketSniffer(*iface)
	}
	if err != nil {
		log.Fatalf("sniffer: %v", err)
	}
	defer s.Close()

	tui := output.NewTerminalUI(*iface, mode)

	var allCreds []protocol.Credential

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	tui.PrintHeader()

	go func() {
		defer func() {
			if *jsonOut != "" {
				if err := output.WriteJSON(allCreds, *jsonOut); err != nil {
					log.Printf("json: %v", err)
				}
				fmt.Printf("\n[*] saved %d credentials → %s\n", len(allCreds), *jsonOut)
			}
		}()

		for pkt := range s.Events() {
			if len(pkt.Payload) == 0 {
				continue
			}

			creds := dispatchProtocol(pkt, protoSet)
			for _, c := range creds {
				tui.AddCredential(c)
				tui.PrintCredential(c)
				allCreds = append(allCreds, c)
			}
		}
	}()

	<-sigCh
	tui.PrintFooter()
	fmt.Println("\n[*] shutting down...")
}

func runOffline(filename string, protoSet map[string]bool, jsonOut string) {
	fmt.Printf("[*] offline mode: %s\n", filename)

	s, err := sniffer.NewPCAPSniffer(filename)
	if err != nil {
		log.Fatalf("pcap: %v", err)
	}
	defer s.Close()

	var allCreds []protocol.Credential

	for pkt := range s.Events() {
		if len(pkt.Payload) == 0 {
			continue
		}
		creds := dispatchProtocol(pkt, protoSet)
		allCreds = append(allCreds, creds...)
		for _, c := range creds {
			fmt.Printf("[%s] %s %s:%s → %s\n", c.Protocol, c.Type, c.SrcIP, c.DstIP, c.String())
		}
	}

	fmt.Printf("\n[*] found %d credentials in %s\n", len(allCreds), filename)

	if jsonOut != "" {
		output.WriteJSON(allCreds, jsonOut)
		fmt.Printf("[*] saved → %s\n", jsonOut)
	}
}

func dispatchProtocol(pkt *sniffer.RawPacket, protoSet map[string]bool) []protocol.Credential {
	isDNSPort := pkt.DstPort == 53 || pkt.SrcPort == 53
	isSMBPort := pkt.DstPort == 445 || pkt.SrcPort == 445
	isLDAPPort := pkt.DstPort == 389 || pkt.SrcPort == 389

	switch {
	case isDNSPort && protoSet["dns"]:
		return protocol.ParseDNS(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
	case isSMBPort && protoSet["smb"]:
		return protocol.ParseSMB(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
	case isLDAPPort && protoSet["ldap"]:
		return protocol.ParseLDAP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
	case protoSet["http"]:
		return protocol.ParseHTTP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
	}
	return nil
}

func parseProtoSet(protoStr string) map[string]bool {
	s := make(map[string]bool)
	for _, p := range strings.Split(protoStr, ",") {
		s[strings.TrimSpace(strings.ToLower(p))] = true
	}
	return s
}
