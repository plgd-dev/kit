package net

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// Addr represents a hostname and an optional port.
// The port == 0 means no port.
// For TCP, port number 0 is reserved and cannot be used.
// For UDP, the source port is optional and 0 means no port.
type Addr struct {
	hostname string
	port     uint16
}

// MakeAddr set all members.
func MakeAddr(hostname string, port uint16) Addr {
	return Addr{hostname: hostname, port: port}
}

// MakeHostname set the hostname and no port.
func MakeHostname(hostname string) Addr {
	return Addr{hostname: hostname}
}

// Parse parses the hostname and port number.
func Parse(a net.Addr) (Addr, error) {
	return ParseString(a.String())
}

// ParseURL parses the hostname and port number.
func ParseURL(url *url.URL) (Addr, error) {
	return ParseString(url.Host)
}

// ParseString parses the hostname and port number.
func ParseString(addr string) (Addr, error) {
	hostname, port, err := net.SplitHostPort(addr)
	if err != nil {
		return Addr{}, err
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return Addr{}, fmt.Errorf("invalid port number: %v", err)
	}
	return MakeAddr(hostname, uint16(portNum)), nil
}

// String formats the address with the optional port.
func (a Addr) String() string {
	if a.port == 0 {
		return a.hostname
	}
	return net.JoinHostPort(a.hostname, strconv.FormatUint(uint64(a.port), 10))
}

// RemovePort sets the zero value.
func (a Addr) RemovePort() Addr {
	a.port = 0
	return a
}

// SetPort changes the port.
func (a Addr) SetPort(port uint16) Addr {
	a.port = port
	return a
}

// GetPort returns the port.
func (a Addr) GetPort() uint16 {
	return a.port
}
