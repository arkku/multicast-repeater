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
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Version can be set at build time with -ldflags "-X main.Version=x.y.z"
var Version = ""

func version() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

const maxPacketSize = 9000
const subnetReloadInterval = 5 * time.Second // Minimum interval between subnet reloads
const maxExternalPrefixes = 256              // Die if we see more external prefixes (misconfiguration)

type ProtocolPreset struct {
	IPv4Group  string
	IPv6Group  string
	Port       int
	KeepSource bool // true for protocols with unicast replies to source IP
	TTL        int  // 0 = try to preserve incoming, >0 = force this value
}

var protocolPresets = map[string]ProtocolPreset{
	"mdns":         {"224.0.0.251", "ff02::fb", 5353, false, 255},
	"ssdp":         {"239.255.255.250", "ff02::c", 1900, true, 0},
	"ws-discovery": {"239.255.255.250", "ff02::c", 3702, true, 0},
	"llmnr":        {"224.0.0.252", "ff02::1:3", 5355, true, 255},
	"coap":         {"224.0.1.187", "ff02::fd", 5683, true, 0},
	"slp":          {"239.255.255.253", "ff02::116", 427, true, 0},
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
	Subnets   []*net.IPNet // For validating source IPs are from this network
	Override  net.IP
	Direction Direction
}

// ContainsIP returns true if the IP is within any of the interface's subnets.
func (cfg *InterfaceConfig) ContainsIP(ip net.IP) bool {
	for _, subnet := range cfg.Subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// ReloadSubnets refreshes the subnets from the interface's current addresses.
func (cfg *InterfaceConfig) ReloadSubnets(family IPFamily) {
	addrs, err := cfg.Interface.Addrs()
	if err != nil {
		return
	}
	var subnets []*net.IPNet
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || !family.matches(ipnet.IP) {
			continue
		}
		if family == IPv6 && !ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		subnets = append(subnets, ipnet)
	}
	cfg.Subnets = subnets
}

// ipToPrefix returns a prefix key for tracking unknown subnets.
// Uses /24 for IPv4 and /64 for IPv6.
func ipToPrefix(ip net.IP) [16]byte {
	var key [16]byte
	if v4 := ip.To4(); v4 != nil {
		// IPv4: use /24 prefix (first 3 bytes), stored in IPv4-mapped position
		key[10] = 0xff
		key[11] = 0xff
		key[12] = v4[0]
		key[13] = v4[1]
		key[14] = v4[2]
		// key[15] = 0 (masked)
	} else if v6 := ip.To16(); v6 != nil {
		// IPv6: use /64 prefix (first 8 bytes)
		copy(key[:8], v6[:8])
	}
	return key
}

// prefixToIP converts a prefix key back to a representative IP for subnet matching.
func prefixToIP(prefix [16]byte, family IPFamily) net.IP {
	if family == IPv4 {
		// IPv4 prefix is stored at bytes 12-14 (IPv4-mapped format)
		return net.IPv4(prefix[12], prefix[13], prefix[14], 1)
	}
	// IPv6: first 8 bytes are the /64 prefix
	ip := make(net.IP, 16)
	copy(ip[:8], prefix[:8])
	ip[15] = 1 // Add a host part
	return ip
}

func buildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, ttl uint8, payload []byte) []byte {
	const ipHeaderLen = 20
	const udpHeaderLen = 8
	totalLen := ipHeaderLen + udpHeaderLen + len(payload)

	packet := make([]byte, totalLen)

	// IPv4 header
	packet[0] = 0x45                // Version 4, IHL 5 (20 bytes)
	packet[1] = 0                   // DSCP + ECN
	packet[2] = byte(totalLen >> 8) // Total length (big endian)
	packet[3] = byte(totalLen)
	// packet[4:6] = ID (0)
	// packet[6:8] = Flags + Fragment offset (0)
	packet[8] = ttl
	packet[9] = syscall.IPPROTO_UDP
	// packet[10:12] = checksum, filled below
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	// IP header checksum
	csum := ipChecksum(packet[:ipHeaderLen])
	packet[10] = byte(csum >> 8)
	packet[11] = byte(csum)

	// UDP header
	packet[20] = byte(srcPort >> 8)
	packet[21] = byte(srcPort)
	packet[22] = byte(dstPort >> 8)
	packet[23] = byte(dstPort)
	udpLen := uint16(udpHeaderLen + len(payload))
	packet[24] = byte(udpLen >> 8)
	packet[25] = byte(udpLen)
	// packet[26:28] = UDP checksum, filled below

	// Payload
	copy(packet[28:], payload)

	// UDP checksum (optional for IPv4, but some receivers may expect it)
	csum = udp4Checksum(srcIP, dstIP, packet[20:])
	packet[26] = byte(csum >> 8)
	packet[27] = byte(csum)

	return packet
}

func buildIPv6UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, hopLimit uint8, payload []byte) []byte {
	const ipv6HeaderLen = 40
	const udpHeaderLen = 8
	udpLen := udpHeaderLen + len(payload)
	totalLen := ipv6HeaderLen + udpLen

	packet := make([]byte, totalLen)

	// IPv6 header
	packet[0] = 0x60 // Version 6
	// packet[1:4] = Traffic class + Flow label (0)
	packet[4] = byte(udpLen >> 8) // Payload length
	packet[5] = byte(udpLen)
	packet[6] = syscall.IPPROTO_UDP // Next header
	packet[7] = hopLimit
	copy(packet[8:24], srcIP.To16())
	copy(packet[24:40], dstIP.To16())

	// UDP header
	packet[40] = byte(srcPort >> 8)
	packet[41] = byte(srcPort)
	packet[42] = byte(dstPort >> 8)
	packet[43] = byte(dstPort)
	packet[44] = byte(udpLen >> 8)
	packet[45] = byte(udpLen)
	// packet[46:48] = UDP checksum, required for IPv6

	// Payload
	copy(packet[48:], payload)

	// UDP checksum (required for IPv6)
	csum := udp6Checksum(srcIP, dstIP, packet[40:])
	packet[46] = byte(csum >> 8)
	packet[47] = byte(csum)

	return packet
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udp4Checksum(srcIP, dstIP net.IP, udpPacket []byte) uint16 {
	// Pseudo-header: src IP (4) + dst IP (4) + zero (1) + protocol (1) + UDP length (2)
	var sum uint32

	src := srcIP.To4()
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])

	dst := dstIP.To4()
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])

	sum += uint32(syscall.IPPROTO_UDP)
	sum += uint32(len(udpPacket))

	// UDP packet (with checksum field as zero)
	for i := 0; i+1 < len(udpPacket); i += 2 {
		if i == 6 {
			continue // Skip checksum field
		}
		sum += uint32(udpPacket[i])<<8 | uint32(udpPacket[i+1])
	}
	if len(udpPacket)%2 == 1 {
		sum += uint32(udpPacket[len(udpPacket)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	result := ^uint16(sum)
	if result == 0 {
		result = 0xffff // Per RFC 768, 0 means "no checksum", so use 0xffff instead
	}
	return result
}

func udp6Checksum(srcIP, dstIP net.IP, udpPacket []byte) uint16 {
	// Pseudo-header for IPv6 UDP checksum
	var sum uint32

	// Source address (16 bytes)
	src := srcIP.To16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(src[i])<<8 | uint32(src[i+1])
	}

	// Destination address (16 bytes)
	dst := dstIP.To16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(dst[i])<<8 | uint32(dst[i+1])
	}

	// UDP length (4 bytes, upper 2 are zero for lengths < 65536)
	udpLen := len(udpPacket)
	sum += uint32(udpLen)

	// Next header (1 byte, but padded to 4)
	sum += uint32(syscall.IPPROTO_UDP)

	// UDP packet
	for i := 0; i+1 < udpLen; i += 2 {
		if i == 6 {
			continue // Skip checksum field itself
		}
		sum += uint32(udpPacket[i])<<8 | uint32(udpPacket[i+1])
	}
	if udpLen%2 == 1 {
		sum += uint32(udpPacket[udpLen-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
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
		var subnets []*net.IPNet
		for _, addr := range addrs {
			var ip net.IP
			var ipnet *net.IPNet
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
				ipnet = a
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
			if ipnet != nil {
				subnets = append(subnets, ipnet)
			}
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
			Subnets:   subnets,
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
	prefix     string
	family     IPFamily
	group      net.IP
	port       int
	ifaces     map[int]*InterfaceConfig
	verbose    bool
	wildcard   bool
	keepSource bool
	strict     bool
	ttl        int // 0 = preserve incoming, >0 = force this value

	conn        net.PacketConn
	rawSender   *rawSender // used to send packets with unowned IPs
	readPacket  func([]byte) (int, int, net.IP, net.Addr, int, error)
	writePacket func([]byte, int, net.IP, *net.UDPAddr, int) error
}

func (server *Server) log(format string, args ...any) {
	log.Printf(server.prefix+": "+format, args...)
}

func (server *Server) Close() error {
	if server.rawSender != nil {
		server.rawSender.Close()
	}
	if server.conn != nil {
		return server.conn.Close()
	}
	return nil
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
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
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
	server.log("Listening on %s", listenAddress)

	if server.family == IPv4 {
		packetConn := ipv4.NewPacketConn(conn)
		if err := packetConn.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface|ipv4.FlagTTL, true); err != nil {
			conn.Close()
			return err
		}
		if err := packetConn.SetMulticastLoopback(false); err != nil {
			server.log("SetMulticastLoopback(false) failed: %v", err)
		}
		if server.ttl > 0 {
			if err := packetConn.SetMulticastTTL(server.ttl); err != nil {
				server.log("SetMulticastTTL(%d) failed: %v", server.ttl, err)
			}
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

		lastTTL := -1
		server.writePacket = func(b []byte, outIf int, srcIP net.IP, dst *net.UDPAddr, ttl int) error {
			// Must set multicast TTL on socket; control message TTL doesn't work for multicast
			if ttl != lastTTL {
				if err := packetConn.SetMulticastTTL(ttl); err != nil {
					if lastTTL == -1 {
						return fmt.Errorf("SetMulticastTTL: %w", err)
					}
					// Non-fatal if it worked before
				} else {
					lastTTL = ttl
				}
			}
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
		if server.ttl > 0 {
			if err := packetConn.SetMulticastHopLimit(server.ttl); err != nil {
				server.log("SetMulticastHopLimit(%d) failed: %v", server.ttl, err)
			}
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

		lastHopLimit := -1
		server.writePacket = func(b []byte, outIf int, srcIP net.IP, dst *net.UDPAddr, hopLimit int) error {
			// Must set multicast hop limit on socket; control message doesn't work for multicast
			if hopLimit != lastHopLimit {
				if err := packetConn.SetMulticastHopLimit(hopLimit); err != nil {
					if lastHopLimit == -1 {
						return fmt.Errorf("SetMulticastHopLimit: %w", err)
					}
					// Non-fatal if it worked before
				} else {
					lastHopLimit = hopLimit
				}
			}
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

// ipToKey converts an IP to a fixed-size key without allocation.
func ipToKey(ip net.IP) [16]byte {
	var key [16]byte
	if len(ip) == 16 {
		copy(key[:], ip)
	} else if len(ip) == 4 {
		// IPv4-mapped IPv6 format: ::ffff:a.b.c.d
		key[10] = 0xff
		key[11] = 0xff
		copy(key[12:], ip)
	}
	return key
}

func (server *Server) Run(wg *sync.WaitGroup, errCh chan<- error) {
	defer wg.Done()

	sourceByInterface := make(map[int]net.IP)
	ownSources := make(map[[16]byte]bool)

	for ifIndex, cfg := range server.ifaces {
		if cfg.Direction.Input {
			server.log("Input from %s (%s)", cfg.Interface.Name, cfg.SourceAddress())
		}
		if cfg.Direction.Output {
			srcIP := cfg.SourceAddress()
			sourceByInterface[ifIndex] = srcIP
			ownSources[ipToKey(srcIP)] = true
			server.log("Output to %s via %s", cfg.Interface.Name, srcIP)
		}
	}

	// Track prefixes that we've tried reloading for but still don't match any interface.
	// This prevents repeated reload attempts for routed/external traffic.
	externalPrefixes := make(map[[16]byte]bool)
	var lastSubnetReload time.Time

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

		srcUDP, _ := srcAddr.(*net.UDPAddr)
		if srcUDP == nil {
			continue
		}

		// Loop prevention: ignore packets from our own source IPs.
		if ownSources[ipToKey(srcUDP.IP)] {
			if server.verbose {
				server.log("Ignoring own packet on %s from %s", inCfg.Interface.Name, srcUDP.IP)
			}
			continue
		}

		// In strict mode, verify the source is on the interface's subnet.
		// This is required for keepSource (can't check against own IP), but
		// also useful to guard against another repeater on the same interfaces.
		if server.strict && !inCfg.ContainsIP(srcUDP.IP) {
			prefix := ipToPrefix(srcUDP.IP)

			// If we haven't seen this prefix, try reloading subnets (might be new, e.g., via IPv6 RA)
			if !externalPrefixes[prefix] {
				// Rate-limit reloads, just in case
				now := time.Now()
				if now.Sub(lastSubnetReload) >= subnetReloadInterval {
					lastSubnetReload = now
					inCfg.ReloadSubnets(server.family)

					// Clean up externalPrefixes in case any now match (subnet may have changed)
					for extPrefix := range externalPrefixes {
						for _, subnet := range inCfg.Subnets {
							if subnet.Contains(prefixToIP(extPrefix, server.family)) {
								delete(externalPrefixes, extPrefix)
								break
							}
						}
					}
				}

				// Check again after (possible) reload
				if inCfg.ContainsIP(srcUDP.IP) {
					server.log("Discovered new subnet on %s containing %s", inCfg.Interface.Name, srcUDP.IP)
					// Fall through to process the packet
				} else {
					// Mark as external so we don't reload again for this prefix
					if len(externalPrefixes) >= maxExternalPrefixes {
						errCh <- fmt.Errorf("too many external prefixes (%d); check firewall/routing", len(externalPrefixes))
						return
					}
					externalPrefixes[prefix] = true
					if server.verbose {
						server.log("Ignoring off-subnet packet on %s from %s", inCfg.Interface.Name, srcUDP.IP)
					}
					continue
				}
			} else {
				// Prefix is already marked external, just ignore
				if server.verbose {
					server.log("Ignoring off-subnet packet on %s from %s", inCfg.Interface.Name, srcUDP.IP)
				}
				continue
			}
		}

		payload := append([]byte(nil), buf[:n]...)
		for outIfIndex, outCfg := range server.ifaces {
			if outIfIndex == inIfIndex || !outCfg.Direction.Output {
				continue
			}

			// Use raw sender when keepSource is enabled (to support non-owned source IPs)
			useRaw := server.rawSender != nil && srcUDP != nil

			// Use configured TTL if set, otherwise preserve incoming
			outTTL := ttlOrHop
			if server.ttl > 0 {
				outTTL = server.ttl
			} else if outTTL <= 0 {
				outTTL = 255
			}

			if server.verbose {
				server.log("Repeating from %s %s to %s (%d bytes, TTL %d)",
					inCfg.Interface.Name, srcAddr, outCfg.Interface.Name, len(payload), outTTL)
			}

			var err error
			if useRaw {
				srcIP := srcUDP.IP
				if outCfg.Override != nil {
					srcIP = outCfg.Override
				}
				err = server.rawSender.Send(outIfIndex, srcIP, server.group, srcUDP.Port, server.port, outTTL, payload)
			} else {
				outSrcIP := sourceByInterface[outIfIndex]
				dst := &net.UDPAddr{IP: server.group, Port: server.port}
				err = server.writePacket(payload, outIfIndex, outSrcIP, dst, outTTL)
			}
			if err != nil {
				errCh <- fmt.Errorf("write to %s: %w", outCfg.Interface.Name, err)
				return
			}
		}
	}
}

func newServer(interfaceList string, family IPFamily, group string, port int, overrides map[string]string, verbose, wildcard, keepSource, strict bool, ttl int) (*Server, error) {
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
		prefix:     family.String(),
		family:     family,
		group:      groupIP,
		port:       port,
		ifaces:     ifaces,
		verbose:    verbose,
		wildcard:   wildcard,
		keepSource: keepSource,
		strict:     strict,
		ttl:        ttl,
	}

	if keepSource {
		rs, err := newRawSender(family, ifaces)
		if err != nil {
			return nil, fmt.Errorf("raw sender: %w", err)
		}
		s.rawSender = rs
	}

	if err := s.configureListener(); err != nil {
		s.Close()
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
	keepSourceFlag := flag.Bool("keep-source", false, "Keep original source IP (overrides -protocol, implies -strict)")
	replaceSourceFlag := flag.Bool("replace-source", false, "Replace source IP with own (overrides -protocol)")
	strictFlag := flag.Bool("strict", false, "Only repeat packets from IPs on the interface's subnet")
	ttlFlag := flag.Int("ttl", -1, "Multicast TTL (0=preserve incoming, >0=force value, -1=protocol default)")
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

	keepSource := preset.KeepSource
	if *keepSourceFlag && *replaceSourceFlag {
		log.Fatal("Cannot use both -keep-source and -replace-source")
	}
	if *keepSourceFlag {
		keepSource = true
	} else if *replaceSourceFlag {
		keepSource = false
	}

	// -keep-source implies -strict (required for loop prevention with raw sockets)
	strict := *strictFlag || keepSource

	// TTL: -1 = use protocol default, 0 = preserve incoming, >0 = force value
	ttl := preset.TTL
	if *ttlFlag >= 0 {
		ttl = *ttlFlag
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
		s, err := newServer(*ifaces4, IPv4, group4, port, ov4, *verbose, *wildcard, keepSource, strict, ttl)
		if err != nil {
			log.Fatal(err)
		}
		servers = append(servers, s)
	}
	if *ifaces6 != "" {
		s, err := newServer(*ifaces6, IPv6, group6, port, ov6, *verbose, *wildcard, keepSource, strict, ttl)
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() { wg.Wait(); close(errCh) }()

	select {
	case sig := <-sigCh:
		log.Printf("Received %v, shutting down...", sig)
		for _, s := range servers {
			s.Close()
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Fatalf("Fatal error: %v", err)
		}
	}
}
