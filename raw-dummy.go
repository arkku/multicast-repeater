//go:build !linux

package main

import (
	"fmt"
	"net"
	"runtime"
)

// rawSender would be used to send raw packets, but this dummy implementation
// fails. The real implementation is platform-specific, e.g., raw-linux.go.
type rawSender struct{}

func newRawSender(family IPFamily, ifaces map[int]*InterfaceConfig) (*rawSender, error) {
	return nil, fmt.Errorf("raw sockets not supported on %s (required for -keep-source)", runtime.GOOS)
}

func (rs *rawSender) Close() {}

func (rs *rawSender) Send(ifIndex int, srcIP, dstIP net.IP, srcPort, dstPort, ttl int, payload []byte) error {
	return fmt.Errorf("raw sockets not supported on %s", runtime.GOOS)
}
