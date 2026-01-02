//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// rawSender sends UDP packets with arbitrary source IPs using raw sockets.
// This is needed for protocols like SSDP where unicast replies must reach
// the original sender, not the repeater.
type rawSender struct {
	family  IPFamily
	sockets map[int]int // ifIndex -> raw socket fd
}

func newRawSender(family IPFamily, ifaces map[int]*InterfaceConfig) (*rawSender, error) {
	rs := &rawSender{
		family:  family,
		sockets: make(map[int]int),
	}

	for ifIndex, cfg := range ifaces {
		if !cfg.Direction.Output {
			continue
		}

		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if family == IPv6 {
			fd, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		}
		if err != nil {
			rs.Close()
			return nil, fmt.Errorf("create raw socket for %s: %w", cfg.Interface.Name, err)
		}

		if family == IPv4 {
			if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
				syscall.Close(fd)
				rs.Close()
				return nil, fmt.Errorf("set IP_HDRINCL for %s: %w", cfg.Interface.Name, err)
			}
		}

		// Bind socket to specific interface (Linux-specific)
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

	var packet []byte
	var sa syscall.Sockaddr

	if rs.family == IPv4 {
		packet = buildIPv4UDPPacket(srcIP, dstIP, uint16(srcPort), uint16(dstPort), uint8(ttl), payload)
		sa = &syscall.SockaddrInet4{Port: 0}
		copy(sa.(*syscall.SockaddrInet4).Addr[:], dstIP.To4())
	} else {
		packet = buildIPv6UDPPacket(srcIP, dstIP, uint16(srcPort), uint16(dstPort), uint8(ttl), payload)
		sa = &syscall.SockaddrInet6{Port: 0}
		copy(sa.(*syscall.SockaddrInet6).Addr[:], dstIP.To16())
	}

	return syscall.Sendto(fd, packet, 0, sa)
}
