package net

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ConnUDP is a udp connection provides Read/Write with context.
//
// Multiple goroutines may invoke methods on a ConnUDP simultaneously.
type ConnUDP struct {
	heartBeat  time.Duration
	connection *net.UDPConn
	lock       sync.Mutex
}

// NewConnUDP creates connection over net.UDPConn.
func NewConnUDP(c *net.UDPConn, heartBeat time.Duration) *ConnUDP {
	connection := ConnUDP{connection: c, heartBeat: heartBeat}
	return &connection
}

// LocalAddr returns the local network address. The Addr returned is shared by all invocations of LocalAddr, so do not modify it.
func (c *ConnUDP) LocalAddr() net.Addr {
	return c.connection.LocalAddr()
}

// RemoteAddr returns the remote network address. The Addr returned is shared by all invocations of RemoteAddr, so do not modify it.
func (c *ConnUDP) RemoteAddr() net.Addr {
	return c.connection.RemoteAddr()
}

// Close closes the connection.
func (c *ConnUDP) Close() error {
	return c.connection.Close()
}

// WriteContext writes data with context.
func (c *ConnUDP) WriteWithContext(ctx context.Context, udpCtx *ConnUDPContext, buffer []byte) error {
	written := 0
	c.lock.Lock()
	defer c.lock.Unlock()
	for written < len(buffer) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err := c.connection.SetWriteDeadline(time.Now().Add(c.heartBeat))
		if err != nil {
			return fmt.Errorf("cannot set write deadline for tcp connection: %v", err)
		}
		n, err := WriteToSessionUDP(c.connection, udpCtx, buffer[written:])
		if err != nil {
			if isTemporary(err) {
				continue
			}
			return fmt.Errorf("cannot write to tcp connection")
		}
		written += n
	}

	return nil
}

// ReadContext reads packet with context.
func (c *ConnUDP) ReadWithContext(ctx context.Context, buffer []byte) (int, *ConnUDPContext, error) {
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				return -1, nil, fmt.Errorf("cannot read from udp connection: %v", ctx.Err())
			}
			return -1, nil, fmt.Errorf("cannot read from udp connection")
		default:
		}

		err := c.connection.SetReadDeadline(time.Now().Add(c.heartBeat))
		if err != nil {
			return -1, nil, fmt.Errorf("cannot set read deadline for udp connection: %v", err)
		}
		n, s, err := ReadFromSessionUDP(c.connection, buffer)
		if err != nil {
			if isTemporary(err) {
				continue
			}
			return -1, nil, fmt.Errorf("cannot read from udp connection: %v", ctx.Err())
		}
		return n, s, err
	}
}
