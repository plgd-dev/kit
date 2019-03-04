package net

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type TLSListener struct {
	tcp       *net.TCPListener
	listener  net.Listener
	heartBeat time.Duration
}

func NewTLSListen(network string, addr string, cfg *tls.Config, heartBeat time.Duration) (*TLSListener, error) {
	tcp, err := newNetTCPListen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("cannot create new tls listener: %v", err)
	}
	tls := tls.NewListener(tcp, cfg)
	return &TLSListener{
		tcp:       tcp,
		listener:  tls,
		heartBeat: heartBeat,
	}, nil
}

func (l *TLSListener) AcceptContext(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				return nil, fmt.Errorf("cannot accept connections: %v", ctx.Err())
			}
			return nil, nil
		default:
		}
		err := l.tcp.SetDeadline(time.Now().Add(l.heartBeat))
		if err != nil {
			return nil, fmt.Errorf("cannot accept connections: %v", err)
		}
		rw, err := l.listener.Accept()
		if err != nil {
			if passError(err) {
				continue
			}
			return nil, fmt.Errorf("cannot accept connections: %v", err)
		}
		return rw, nil
	}
}

func (l *TLSListener) SetDeadline(t time.Time) error {
	return l.tcp.SetDeadline(t)
}

func (l *TLSListener) Accept() (net.Conn, error) {
	return l.AcceptContext(context.Background())
}

func (l *TLSListener) Close() error {
	return l.listener.Close()
}

func (l *TLSListener) Addr() net.Addr {
	return l.listener.Addr()
}
