package net

import (
	"net"
	"strings"
)

func passError(err error) bool {
	if netErr, ok := err.(net.Error); ok && (netErr.Temporary() || netErr.Timeout()) {
		return true
	}
	if strings.Contains(err.Error(), "i/o timeout") {
		return true
	}
	return false
}
