//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// rawSender sends IPv4 UDP packets with arbitrary source IPs using raw sockets.
// This is needed for protocols like SSDP where unicast replies must reach
// the original sender, not the repeater. Only IPv4 is supported because Linux
// IPv6 raw sockets do not support IP_HDRINCL for source IP spoofing.
type rawSender struct {
	sockets map[int]int // ifIndex -> raw socket fd
}

func newRawSender(family IPFamily, ifaces map[int]*InterfaceConfig, includeInput bool) (*rawSender, error) {
	if family != IPv4 {
		return nil, fmt.Errorf("raw sockets only supported for IPv4 (IPv6 lacks IP_HDRINCL)")
	}

	rs := &rawSender{
		sockets: make(map[int]int),
	}

	for ifIndex, cfg := range ifaces {
		if !cfg.Direction.Output && !(includeInput && cfg.Direction.Input) {
			continue
		}

		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			rs.Close()
			return nil, fmt.Errorf("create raw socket for %s: %w", cfg.Interface.Name, err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			rs.Close()
			return nil, fmt.Errorf("set IP_HDRINCL for %s: %w", cfg.Interface.Name, err)
		}

		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, cfg.Interface.Name); err != nil {
			syscall.Close(fd)
			rs.Close()
			return nil, fmt.Errorf("bind to %s: %w", cfg.Interface.Name, err)
		}

		rs.sockets[ifIndex] = fd
	}

	return rs, nil
}

func (rs *rawSender) Close() {
	for _, fd := range rs.sockets {
		syscall.Close(fd)
	}
}

func (rs *rawSender) Send(ifIndex int, srcIP, dstIP net.IP, srcPort, dstPort, ttl int, payload []byte) error {
	fd, ok := rs.sockets[ifIndex]
	if !ok {
		return fmt.Errorf("no raw socket for interface %d", ifIndex)
	}

	packet := buildIPv4UDPPacket(srcIP, dstIP, uint16(srcPort), uint16(dstPort), uint8(ttl), payload)
	sa := &syscall.SockaddrInet4{Port: 0}
	copy(sa.Addr[:], dstIP.To4())

	return syscall.Sendto(fd, packet, 0, sa)
}
