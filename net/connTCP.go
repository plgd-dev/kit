package net

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type ConnTCP struct {
	heartBeat  time.Duration
	connection net.Conn // i/o connection if TCP was used
	readBuffer *bufio.Reader
	lock       sync.Mutex
}

func NewConnTCP(c net.Conn, heartBeat time.Duration) *ConnTCP {
	connection := ConnTCP{
		connection: c,
		heartBeat:  heartBeat,
		readBuffer: acquireReader(c),
	}
	return &connection
}

func (c *ConnTCP) LocalAddr() net.Addr {
	return c.connection.LocalAddr()
}

func (c *ConnTCP) RemoteAddr() net.Addr {
	return c.connection.RemoteAddr()
}

func (c *ConnTCP) Close() error {
	err := c.connection.Close()
	releaseReader(c.readBuffer)
	return err
}

func (c *ConnTCP) WriteContext(ctx context.Context, buffer []byte) error {
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
		n, err := c.connection.Write(buffer[written:])

		if err != nil {
			if passError(err) {
				continue
			}
			return fmt.Errorf("cannot write to tcp connection")
		}
		written += n
	}
	return nil
}

func (c *ConnTCP) ReadFullContext(ctx context.Context, buffer []byte) error {
	offset := 0
	for offset < len(buffer) {
		n, err := c.ReadContext(ctx, buffer[offset:])
		if err != nil {
			return fmt.Errorf("cannot read full from tcp connection: %v", err)
		}
		offset += n
	}
	return nil
}

func (c *ConnTCP) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				return -1, fmt.Errorf("cannot read from tcp connection: %v", ctx.Err())
			}
			return -1, fmt.Errorf("cannot read from tcp connection")
		default:
		}

		err := c.connection.SetReadDeadline(time.Now().Add(c.heartBeat))
		if err != nil {
			return -1, fmt.Errorf("cannot set read deadline for tcp connection: %v", err)
		}
		n, err := c.readBuffer.Read(buffer)
		if err != nil {
			if passError(err) {
				continue
			}
			return -1, fmt.Errorf("cannot read from tcp connection: %v", err)
		}
		return n, err
	}
}
