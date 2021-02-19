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
	scheme   string
	hostname string
	port     uint16
}

// MakeAddr set all members.
func MakeAddr(scheme, hostname string, port uint16) Addr {
	return Addr{scheme: scheme, hostname: hostname, port: port}
}

// MakeHostname set the hostname and no port.
func MakeHostname(hostname string) Addr {
	return Addr{hostname: hostname}
}

// Parse parses the hostname and port number.
func Parse(scheme string, a net.Addr) (Addr, error) {
	return ParseString(scheme, a.String())
}

// ParseURL parses the hostname and port number.
func ParseURL(url *url.URL) (Addr, error) {
	return ParseString(url.Scheme, url.Host)
}

// ParseString parses the hostname and port number.
func ParseString(scheme, addr string) (Addr, error) {
	hostname, port, err := net.SplitHostPort(addr)
	if err != nil {
		return Addr{}, err
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return Addr{}, fmt.Errorf("invalid port number: %w", err)
	}
	return MakeAddr(scheme, hostname, uint16(portNum)), nil
}

// String formats the address with the optional port.
func (a Addr) String() string {
	if a.port == 0 {
		return a.hostname
	}
	return net.JoinHostPort(a.hostname, strconv.FormatUint(uint64(a.port), 10))
}

// URL formats the scheme with address and with the optional port.
func (a Addr) URL() string {
	return a.scheme + "://" + a.String()
}

// RemovePort sets the zero value.
func (a Addr) RemovePort() Addr {
	return a.SetPort(0)
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

// SetScheme changes the scheme.
func (a Addr) SetScheme(scheme string) Addr {
	a.scheme = scheme
	return a
}

// RemoveScheme sets the empty value.
func (a Addr) RemoveScheme() Addr {
	return a.SetScheme("")
}

// GetScheme returns the scheme.
func (a Addr) GetScheme() string {
	return a.scheme
}

// GetHostname returns the hostname
func (a Addr) GetHostname() string {
	return a.hostname
}

// SetHostname sets hostname
func (a Addr) SetHostname(hostname string) Addr {
	a.hostname = hostname
	return a
}
