package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/jankesec/driftnet2/internal/buildinfo"
	"github.com/jankesec/driftnet2/pkg/audit"
	"github.com/jankesec/driftnet2/pkg/output"
	"github.com/jankesec/driftnet2/pkg/protocol"
	"github.com/jankesec/driftnet2/pkg/sniffer"
)

const banner = `
    ____       _  ______            __   ___  
   / __ \_____(_)/ __/ /_____  ___ / /_ |__ \ 
  / / / / ___/ // /_/ __/ __ \/ _ \ __/ __/ / 
 / /_/ / /  / // __/ /_/ / / /  __/ /_ / __/  
/_____/_/  /_//_/    \__/_/ /_/\___/\__|____/ 

      kernel-level packet sniffer & credential extractor
`

var supportedProtocols = map[string]struct{}{
	"dns": {}, "ftp": {}, "http": {}, "imap": {}, "ldap": {},
	"pop3": {}, "smb": {}, "smtp": {}, "telnet": {},
}

func main() {
	iface := flag.String("iface", "", "network interface (e.g. eth0, en0)")
	jsonOut := flag.String("output", "", "JSON output file")
	protocols := flag.String("proto", "http,dns,smb,ldap,ftp,telnet,pop3,imap,smtp", "protocols to sniff")
	pcapRead := flag.String("pcap", "", "read from PCAP file (offline mode)")
	pcapWrite := flag.String("w", "", "write captured packets to PCAP file")
	verbose := flag.Bool("v", false, "verbose output (show all protocol events)")
	bpfPath := flag.String("bpf", "", "path to compiled eBPF object (default: auto-detect)")
	audit := flag.Bool("audit", false, "print a credential exposure audit report at the end")
	auditOut := flag.String("audit-output", "", "write the audit report as JSON to a file")
	showVersion := flag.Bool("version", false, "print version and build information")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}

	protoSet := parseProtoSet(*protocols)
	if unknown := unknownProtocols(protoSet); len(unknown) > 0 {
		log.Fatalf("unsupported protocol(s): %s", strings.Join(unknown, ", "))
	}

	fmt.Print(banner)

	if *pcapRead != "" {
		runOffline(*pcapRead, protoSet, *jsonOut, *verbose, *audit, *auditOut)
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

	mode := "PCAP"
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
			log.Printf("XDP failed: %v — falling back to libpcap", err)
			hasXDP = false
			mode = "PCAP"
		}
	}
	if !hasXDP {
		sniff, err = sniffer.NewAFPacketSniffer(*iface)
	}
	if err != nil {
		log.Fatalf("sniffer: %v", err)
	}
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

	var allCreds []protocol.Credential
	seen := make(map[string]bool)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	tui.PrintHeader()

	var processor sync.WaitGroup
	processor.Add(1)
	go func() {
		defer processor.Done()
		for pkt := range sniff.Events() {
			if pcapW != nil {
				if err := pcapW.WritePacket(pkt); err != nil {
					log.Printf("pcap write: %v", err)
				}
			}

			if len(pkt.Payload) == 0 {
				continue
			}

			creds := credentialsFromPacket(pkt, protoSet)
			for _, c := range creds {
				key := dedupKey(c)
				if seen[key] {
					continue
				}
				seen[key] = true
				allCreds = append(allCreds, c)

				tui.AddCredential(c)
				tui.PrintCredential(c)
			}
		}
	}()

	<-sigCh
	signal.Stop(sigCh)
	if err := sniff.Close(); err != nil {
		log.Printf("sniffer close: %v", err)
	}
	processor.Wait()

	tui.PrintFooter()
	fmt.Println("\n[*] shutting down...")

	finalCreds := make([]protocol.Credential, len(allCreds))
	copy(finalCreds, allCreds)

	if *jsonOut != "" {
		if err := output.WriteJSON(finalCreds, *jsonOut); err != nil {
			log.Printf("json: %v", err)
		} else {
			fmt.Printf("[*] saved %d credentials → %s\n", len(finalCreds), *jsonOut)
		}
	}

	if *audit {
		emitAudit(finalCreds, *auditOut)
	}
}

func runOffline(filename string, protoSet map[string]bool, jsonOut string, verbose, audit bool, auditOut string) {
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
		creds := credentialsFromPacket(pkt, protoSet)
		for _, c := range creds {
			key := dedupKey(c)
			if seen[key] {
				continue
			}
			seen[key] = true
			allCreds = append(allCreds, c)
			// The finding stream intentionally displays captured values to the
			// authorized operator; private file exports remain mode 0600.
			// lgtm[go/clear-text-logging]
			fmt.Printf("[%s] %s %s → %s — %s\n",
				c.Protocol, c.Type, c.SrcIP, destination(c), c.String())
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
		} else {
			fmt.Printf("[*] saved → %s\n", jsonOut)
		}
	}

	if audit {
		emitAudit(allCreds, auditOut)
	}
}

// emitAudit prints a credential exposure report and optionally writes it as JSON.
func emitAudit(creds []protocol.Credential, auditOut string) {
	rep := audit.Analyze(creds)
	fmt.Println()
	fmt.Print(rep.Text())
	if auditOut == "" {
		return
	}
	data, err := rep.JSON()
	if err != nil {
		log.Printf("audit json: %v", err)
		return
	}
	if err := output.WritePrivateFile(auditOut, data); err != nil {
		log.Printf("audit output: %v", err)
		return
	}
	fmt.Printf("[*] audit report → %s\n", auditOut)
}

func credentialsFromPacket(pkt *sniffer.RawPacket, protoSet map[string]bool) []protocol.Credential {
	creds := dispatchProtocol(pkt, protoSet)
	if pkt.Timestamp.IsZero() {
		return creds
	}
	for i := range creds {
		creds[i].Timestamp = pkt.Timestamp
	}
	return creds
}

func destination(c protocol.Credential) string {
	if c.DstPort == 0 {
		return c.DstIP
	}
	return net.JoinHostPort(c.DstIP, strconv.Itoa(int(c.DstPort)))
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
		if normalized := strings.TrimSpace(strings.ToLower(p)); normalized != "" {
			s[normalized] = true
		}
	}
	return s
}

func unknownProtocols(protoSet map[string]bool) []string {
	var unknown []string
	for proto := range protoSet {
		if _, ok := supportedProtocols[proto]; !ok {
			unknown = append(unknown, proto)
		}
	}
	sort.Strings(unknown)
	return unknown
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
