package net

import goNet "net"

// https://golang.org/src/net/ip.go - it is not exported

// Index of rightmost occurrence of b in s.
func last(s string, b byte) int {
	i := len(s)
	for i--; i >= 0; i-- {
		if s[i] == b {
			break
		}
	}
	return i
}

func splitHostZone(s string) (host, zone string) {
	// The IPv6 scoped addressing zone identifier starts after the
	// last percent sign.
	if i := last(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

// parseIPv6Zone parses s as a literal IPv6 address and its associated zone
// identifier which is described in RFC 4007.
func parseIPv6Zone(s string) (goNet.IP, string) {
	s, zone := splitHostZone(s)
	return goNet.ParseIP(s), zone
}

// ParseIPZone parses s as an IP address, return it and its associated zone
// identifier (IPv6 only).
func ParseIPZone(s string) (goNet.IP, string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return goNet.ParseIP(s), ""
		case ':':
			return parseIPv6Zone(s)
		}
	}
	return nil, ""
}
