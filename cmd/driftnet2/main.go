package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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
	flag.Parse()

	fmt.Print(banner)

	if *iface == "" {
		fmt.Println("usage: driftnet2 -iface <interface> [flags]")
		fmt.Println("\nflags:")
		flag.PrintDefaults()
		fmt.Println("\nexamples:")
		fmt.Println("  driftnet2 -iface eth0")
		fmt.Println("  driftnet2 -iface en0 --proto http")
		fmt.Println("  driftnet2 -iface eth0 -output creds.json")
		os.Exit(1)
	}

	if !sniffer.IsInterfaceValid(*iface) {
		log.Fatalf("interface %s not found", *iface)
	}

	mode := "AF_PACKET"
	fmt.Printf("[*] interface: %-8s  mode: %-10s  proto: %s\n\n", *iface, mode, *protocols)

	s, err := sniffer.NewAFPacketSniffer(*iface)
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

			var creds []protocol.Credential

			isDNSPort := pkt.DstPort == 53 || pkt.SrcPort == 53
			isSMBPort := pkt.DstPort == 445 || pkt.SrcPort == 445
			isLDAPPort := pkt.DstPort == 389 || pkt.SrcPort == 389

			switch {
			case isDNSPort:
				creds = protocol.ParseDNS(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
			case isSMBPort:
				creds = protocol.ParseSMB(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
			case isLDAPPort:
				creds = protocol.ParseLDAP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
			default:
				creds = protocol.ParseHTTP(pkt.Payload, pkt.SrcIP, pkt.DstIP, pkt.DstPort)
			}

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
