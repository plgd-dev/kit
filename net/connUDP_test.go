package net

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConnUDP_WriteContext(t *testing.T) {
	peerAddr := "127.0.0.1:2154"
	b, err := net.ResolveUDPAddr("udp", peerAddr)
	assert.NoError(t, err)

	ctxCanceled, ctxCancel := context.WithCancel(context.Background())
	ctxCancel()

	type args struct {
		ctx    context.Context
		udpCtx *ConnUDPContext
		buffer []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				ctx:    context.Background(),
				udpCtx: NewConnUDPContext(b, nil),
				buffer: []byte("hello world"),
			},
		},
		{
			name: "cancelled",
			args: args{
				ctx:    ctxCanceled,
				buffer: []byte("hello world"),
			},
			wantErr: true,
		},
	}

	a, err := net.ResolveUDPAddr("udp", "127.0.0.1:")
	assert.NoError(t, err)
	l1, err := net.ListenUDP("udp", a)
	assert.NoError(t, err)
	err = SetUDPSocketOptions(l1)
	assert.NoError(t, err)
	c1 := NewConnUDP(l1, time.Millisecond*100)
	defer c1.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l2, err := net.ListenUDP("udp", b)
	err = SetUDPSocketOptions(l2)
	assert.NoError(t, err)
	c2 := NewConnUDP(l2, time.Millisecond*100)
	defer c2.Close()

	go func() {
		b := make([]byte, 1024)
		_, udpCtx, err := c2.ReadContext(ctx, b)
		if err != nil {
			return
		}
		correctSource(udpCtx.context)
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = c1.WriteContext(tt.args.ctx, tt.args.udpCtx, tt.args.buffer)

			c1.LocalAddr()
			c1.RemoteAddr()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
