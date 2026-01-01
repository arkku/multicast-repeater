// multicast-repeater
//
// A simple program to listen on IPv4 and IPv6 multicast groups on specified
// interfaces and repeat/duplicate the packets to other interfaces. For
// example, to allow mDNS service discovery across VLAN boundaries. Interfaces
// can be specified as input only (listen on), output only (repeat to), or
// both (the default).
//
// The packets are preserved exactly as they are, other than the source address
// is changed to the address of the output interface. (The address can be
// overridden for specific interfaces is desired.)
//
// I made this with the help of AI because Avahi seems to modify the packets
// and this causes some issues with more picky IoT devices.
//
// Note that this does not do anything for broadcast or unicast packets;
// another reflector (or nftables `dup` rule) is needed for those.
//
// - Kimmo Kulovesi, https://github.com/arkku/
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}

const maxPacketSize = 9000

type ProtocolPreset struct {
	IPv4Group string
	IPv6Group string
	Port      int
}

var protocolPresets = map[string]ProtocolPreset{
	"mdns":         {"224.0.0.251", "ff02::fb", 5353},
	"ssdp":         {"239.255.255.250", "ff02::c", 1900},
	"ws-discovery": {"239.255.255.250", "ff02::c", 3702},
	"llmnr":        {"224.0.0.252", "ff02::1:3", 5355},
	"coap":         {"224.0.1.187", "ff02::fd", 5683},
	"slp":          {"239.255.255.253", "ff02::116", 427},
}

var defaultPreset = protocolPresets["mdns"]

type IPFamily int

const (
	IPv4 IPFamily = 4
	IPv6 IPFamily = 6
)

func (f IPFamily) String() string {
	if f == IPv4 {
		return "IPv4"
	}
	return "IPv6"
}

func (f IPFamily) matches(ip net.IP) bool {
	if ip == nil {
		return false
	}
	isV4 := ip.To4() != nil
	return (f == IPv4) == isV4
}

type Direction struct {
	Input  bool
	Output bool
}

var (
	dirBoth   = Direction{Input: true, Output: true}
	dirInput  = Direction{Input: true, Output: false}
	dirOutput = Direction{Input: false, Output: true}
)

// Parses a direction suffix (e.g., "=in", "=out", "=inout"), if any.
func parseDirection(token string) (name string, dir Direction, err error) {
	name, suffix, hasSuffix := strings.Cut(token, "=")
	if !hasSuffix {
		return name, dirBoth, nil
	}
	switch strings.ToLower(suffix) {
	case "in":
		return name, dirInput, nil
	case "out":
		return name, dirOutput, nil
	case "inout", "both", "":
		return name, dirBoth, nil
	default:
		return "", Direction{}, fmt.Errorf("invalid direction %q (use in, out, or inout)", suffix)
	}
}

type InterfaceConfig struct {
	Interface *net.Interface
	Addresses []net.IP
	Override  net.IP
	Direction Direction
}

func parseInterfaceList(list string, family IPFamily, overrides map[string]string) (map[int]*InterfaceConfig, error) {
	result := map[int]*InterfaceConfig{}
	if list == "" {
		return result, nil
	}

	for token := range strings.SplitSeq(list, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		ifaceName, dir, err := parseDirection(token)
		if err != nil {
			return nil, err
		}
		ifaceName = strings.TrimSpace(ifaceName)
		if ifaceName == "" {
			continue
		}

		ifaceObj, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", ifaceName, err)
		}

		addrs, err := ifaceObj.Addrs()
		if err != nil {
			return nil, fmt.Errorf("addresses for %s: %w", ifaceName, err)
		}

		var ips []net.IP
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if ip == nil || !family.matches(ip) {
				continue
			}
			if family == IPv6 && !ip.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ip)
		}

		if len(ips) == 0 {
			if family == IPv6 {
				return nil, fmt.Errorf("interface %s has no IPv6 link-local address", ifaceName)
			}
			return nil, fmt.Errorf("interface %s has no %v addresses", ifaceName, family)
		}

		var overrideIP net.IP
		if overrideStr, ok := overrides[ifaceName]; ok && overrideStr != "" {
			overrideIP = net.ParseIP(overrideStr)
			if overrideIP == nil {
				return nil, fmt.Errorf("invalid override %q for %s", overrideStr, ifaceName)
			}
			if !family.matches(overrideIP) {
				return nil, fmt.Errorf("override %s is not %v for %s", overrideIP, family, ifaceName)
			}
		}

		result[ifaceObj.Index] = &InterfaceConfig{
			Interface: ifaceObj,
			Addresses: ips,
			Override:  overrideIP,
			Direction: dir,
		}
	}

	return result, nil
}

func parseOverrides(input string) (map[string]string, error) {
	overrides := map[string]string{}
	if input == "" {
		return overrides, nil
	}
	for token := range strings.SplitSeq(input, ",") {
		pair := strings.TrimSpace(token)
		if pair == "" {
			continue
		}
		kvParts := strings.SplitN(pair, "=", 2)
		if len(kvParts) != 2 {
			return nil, fmt.Errorf("invalid override pair %q (expected iface=addr)", pair)
		}
		key := strings.TrimSpace(kvParts[0])
		value := strings.TrimSpace(kvParts[1])
		overrides[key] = value
	}
	return overrides, nil
}

func (cfg *InterfaceConfig) SourceAddress() net.IP {
	if cfg.Override != nil {
		return cfg.Override
	}
	// Addresses are pre-filtered and non-empty.
	return cfg.Addresses[0]
}

type Server struct {
	prefix   string
	family   IPFamily
	group    net.IP
	port     int
	ifaces   map[int]*InterfaceConfig
	verbose  bool
	wildcard bool

	conn        net.PacketConn
	readPacket  func([]byte) (int, int, net.IP, net.Addr, int, error)
	writePacket func([]byte, int, net.IP, *net.UDPAddr, int) error
}

func (server *Server) log(format string, args ...any) {
	log.Printf(server.prefix+": "+format, args...)
}

func (server *Server) configureListener() error {
	var network, listenAddress string
	if server.family == IPv4 {
		network = "udp4"
		if server.wildcard {
			listenAddress = fmt.Sprintf(":%d", server.port)
		} else {
			listenAddress = fmt.Sprintf("%s:%d", server.group, server.port)
		}
	} else {
		network = "udp6"
		if server.wildcard {
			listenAddress = fmt.Sprintf("[::]:%d", server.port)
		} else {
			listenAddress = fmt.Sprintf("[%s]:%d", server.group, server.port)
		}
	}

	listenConfig := net.ListenConfig{
		Control: func(_, _ string, rawConn syscall.RawConn) error {
			var controlError error
			if err := rawConn.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					controlError = fmt.Errorf("setsockopt SO_REUSEADDR: %w", err)
					return
				}
			}); err != nil {
				return fmt.Errorf("raw control error: %w", err)
			}
			return controlError
		},
	}

	conn, err := listenConfig.ListenPacket(context.Background(), network, listenAddress)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", network, listenAddress, err)
	}
	server.conn = conn

	if server.family == IPv4 {
		packetConn := ipv4.NewPacketConn(conn)
		if err := packetConn.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface|ipv4.FlagTTL, true); err != nil {
			conn.Close()
			return err
		}
		if err := packetConn.SetMulticastLoopback(false); err != nil {
			server.log("SetMulticastLoopback(false) failed: %v", err)
		}

		for _, cfg := range server.ifaces {
			if !cfg.Direction.Input {
				continue
			}
			if err := packetConn.JoinGroup(cfg.Interface, &net.UDPAddr{IP: server.group}); err != nil {
				conn.Close()
				return fmt.Errorf("join group %s on %s: %w", server.group, cfg.Interface.Name, err)
			}
			server.log("Joined %s on %s", server.group, cfg.Interface.Name)
		}

		server.readPacket = func(buf []byte) (int, int, net.IP, net.Addr, int, error) {
			n, cm, src, err := packetConn.ReadFrom(buf)
			if err != nil {
				return 0, 0, nil, nil, 0, err
			}
			var ifIndex int
			var dst net.IP
			var ttl int
			if cm != nil {
				ifIndex = cm.IfIndex
				dst = cm.Dst
				ttl = cm.TTL
			}
			return n, ifIndex, dst, src, ttl, nil
		}

		server.writePacket = func(b []byte, outIf int, srcIP net.IP, dst *net.UDPAddr, ttl int) error {
			cm := &ipv4.ControlMessage{
				IfIndex: outIf,
				Src:     srcIP,
				TTL:     ttl,
			}
			_, err := packetConn.WriteTo(b, cm, dst)
			return err
		}
	} else {
		packetConn := ipv6.NewPacketConn(conn)
		if err := packetConn.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface|ipv6.FlagHopLimit, true); err != nil {
			conn.Close()
			return err
		}
		if err := packetConn.SetMulticastLoopback(false); err != nil {
			server.log("SetMulticastLoopback(false) failed: %v", err)
		}

		for _, cfg := range server.ifaces {
			if !cfg.Direction.Input {
				continue
			}
			if err := packetConn.JoinGroup(cfg.Interface, &net.UDPAddr{IP: server.group}); err != nil {
				conn.Close()
				return fmt.Errorf("join group %s on %s: %w", server.group, cfg.Interface.Name, err)
			}
			server.log("Joined %s on %s", server.group, cfg.Interface.Name)
		}

		server.readPacket = func(buf []byte) (int, int, net.IP, net.Addr, int, error) {
			n, cm, src, err := packetConn.ReadFrom(buf)
			if err != nil {
				return 0, 0, nil, nil, 0, err
			}
			var ifIndex int
			var dst net.IP
			var hopLimit int
			if cm != nil {
				ifIndex = cm.IfIndex
				dst = cm.Dst
				hopLimit = cm.HopLimit
			}
			return n, ifIndex, dst, src, hopLimit, nil
		}

		server.writePacket = func(b []byte, outIf int, srcIP net.IP, dst *net.UDPAddr, hopLimit int) error {
			cm := &ipv6.ControlMessage{
				IfIndex:  outIf,
				Src:      srcIP,
				HopLimit: hopLimit,
			}
			_, err := packetConn.WriteTo(b, cm, dst)
			return err
		}
	}

	return nil
}

func (server *Server) Run(wg *sync.WaitGroup, errCh chan<- error) {
	defer wg.Done()

	sourceByInterface := make(map[int]net.IP)
	ownSources := make(map[string]bool)

	for ifIndex, cfg := range server.ifaces {
		if !cfg.Direction.Output {
			continue
		}
		srcIP := cfg.SourceAddress()
		sourceByInterface[ifIndex] = srcIP
		ownSources[srcIP.String()] = true
		if server.verbose {
			server.log("Output %s via %s", cfg.Interface.Name, srcIP)
		}
	}

	buf := make([]byte, maxPacketSize)
	for {
		n, inIfIndex, dst, srcAddr, ttlOrHop, err := server.readPacket(buf)
		if err != nil {
			errCh <- err
			return
		}
		if dst == nil || !dst.Equal(server.group) {
			continue
		}
		inCfg, ok := server.ifaces[inIfIndex]
		if !ok || !inCfg.Direction.Input {
			continue
		}

		// Loop prevention: ignore packets from our own source addresses.
		if srcUDP, ok := srcAddr.(*net.UDPAddr); ok && ownSources[srcUDP.IP.String()] {
			if server.verbose {
				server.log("Ignoring own packet on %s from %s", inCfg.Interface.Name, srcUDP.IP)
			}
			continue
		}

		payload := append([]byte(nil), buf[:n]...)
		for outIfIndex, outCfg := range server.ifaces {
			if outIfIndex == inIfIndex || !outCfg.Direction.Output {
				continue
			}
			outSrcIP := sourceByInterface[outIfIndex]
			if server.verbose {
				server.log("Repeating from %s %s to %s (%d bytes)",
					inCfg.Interface.Name, srcAddr, outCfg.Interface.Name, len(payload))
			}
			dst := &net.UDPAddr{IP: server.group, Port: server.port}
			if err := server.writePacket(payload, outIfIndex, outSrcIP, dst, ttlOrHop); err != nil {
				server.log("Warning: write to %s failed: %v", outCfg.Interface.Name, err)
			}
		}
	}
}

func newServer(interfaceList string, family IPFamily, group string, port int, overrides map[string]string, verbose, wildcard bool) (*Server, error) {
	ifaces, err := parseInterfaceList(interfaceList, family, overrides)
	if err != nil {
		return nil, err
	}
	groupIP := net.ParseIP(group)
	if groupIP == nil {
		return nil, fmt.Errorf("invalid multicast group: %s", group)
	}

	if len(ifaces) < 2 {
		return nil, fmt.Errorf("need at least 2 interfaces to repeat between for %v", family)
	}

	var hasInput, hasOutput bool
	for _, cfg := range ifaces {
		if cfg.Direction.Input {
			hasInput = true
		}
		if cfg.Direction.Output {
			hasOutput = true
		}
		if hasInput && hasOutput {
			break
		}
	}
	if !hasInput {
		return nil, fmt.Errorf("no input interfaces configured for %v", family)
	}
	if !hasOutput {
		return nil, fmt.Errorf("no output interfaces configured for %v", family)
	}

	s := &Server{
		prefix:   family.String(),
		family:   family,
		group:    groupIP,
		port:     port,
		ifaces:   ifaces,
		verbose:  verbose,
		wildcard: wildcard,
	}
	if err := s.configureListener(); err != nil {
		return nil, err
	}
	return s, nil
}

func knownProtocols() string {
	names := make([]string, 0, len(protocolPresets))
	for name := range protocolPresets {
		names = append(names, name)
	}
	// Sort for deterministic help output.
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[i] > names[j] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return strings.Join(names, ", ")
}

func main() {
	ifaces := flag.String("i", "", "Interfaces for both IPv4 and IPv6")
	ifaces4 := flag.String("4", "", "Interfaces for IPv4")
	ifaces6 := flag.String("6", "", "Interfaces for IPv6")
	protocolFlag := flag.String("protocol", "", "Protocol preset (default: mdns): "+knownProtocols())
	portFlag := flag.String("p", "", "UDP port or service name (overrides -protocol)")
	group4Flag := flag.String("group4", "", "IPv4 multicast group (overrides -protocol)")
	group6Flag := flag.String("group6", "", "IPv6 multicast group (overrides -protocol)")
	overrides4 := flag.String("override4", "", "IPv4 override outgoing address (iface=addr)")
	overrides6 := flag.String("override6", "", "IPv6 override outgoing address (iface=addr)")
	wildcard := flag.Bool("wildcard", false, "Bind to wildcard address instead of multicast group")
	showVersion := flag.Bool("version", false, "Print version and exit")
	verbose := flag.Bool("v", false, "Verbose output (debug)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "multicast-repeater\nKimmo Kulovesi, https://github.com/arkku/\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s <-i|-4|-6> <interfaces> [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Repeats multicast packets between network interfaces.")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nInterface syntax: name[=in|out|inout], e.g., eth0,eth1=in,eth2=out")
	}
	flag.Parse()

	if *showVersion {
		fmt.Println("multicast-repeater", version())
		os.Exit(0)
	}

	if *ifaces == "" && *ifaces4 == "" && *ifaces6 == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *ifaces != "" {
		if *ifaces4 != "" || *ifaces6 != "" {
			fmt.Fprintln(os.Stderr, "Error: use either -i or -4/-6, not both")
			os.Exit(2)
		}
		*ifaces4, *ifaces6 = *ifaces, *ifaces
	}

	preset := defaultPreset
	if *protocolFlag != "" {
		p, ok := protocolPresets[strings.ToLower(*protocolFlag)]
		if !ok {
			log.Fatalf("Unknown protocol %q; known protocols: %s", *protocolFlag, knownProtocols())
		}
		preset = p
	}

	group4 := preset.IPv4Group
	group6 := preset.IPv6Group
	port := preset.Port
	if *group4Flag != "" {
		group4 = *group4Flag
	}
	if *group6Flag != "" {
		group6 = *group6Flag
	}
	if *portFlag != "" {
		if p, err := strconv.Atoi(*portFlag); err == nil {
			port = p
		} else if p, err := net.LookupPort("udp", *portFlag); err == nil {
			port = p
		} else {
			log.Fatalf("Invalid port: %s", *portFlag)
		}
	}

	validateGroup := func(addr string, family IPFamily) {
		ip := net.ParseIP(addr)
		if ip == nil {
			log.Fatalf("Invalid %v multicast group address: %s", family, addr)
		}
		if !ip.IsMulticast() {
			log.Fatalf("%s is not a multicast address", addr)
		}
		if !family.matches(ip) {
			log.Fatalf("%s is not an %v address", addr, family)
		}
	}
	if *ifaces4 != "" {
		validateGroup(group4, IPv4)
	}
	if *ifaces6 != "" {
		validateGroup(group6, IPv6)
	}

	mustParseOverrides := func(input, name string) map[string]string {
		m, err := parseOverrides(input)
		if err != nil {
			log.Fatalf("Error parsing %s: %v", name, err)
		}
		return m
	}
	ov4 := mustParseOverrides(*overrides4, "-override4")
	ov6 := mustParseOverrides(*overrides6, "-override6")

	var servers []*Server
	if *ifaces4 != "" {
		s, err := newServer(*ifaces4, IPv4, group4, port, ov4, *verbose, *wildcard)
		if err != nil {
			log.Fatal(err)
		}
		servers = append(servers, s)
	}
	if *ifaces6 != "" {
		s, err := newServer(*ifaces6, IPv6, group6, port, ov6, *verbose, *wildcard)
		if err != nil {
			log.Fatal(err)
		}
		servers = append(servers, s)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		wg.Add(1)
		go s.Run(&wg, errCh)
	}

	go func() { wg.Wait(); close(errCh) }()
	if err := <-errCh; err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
