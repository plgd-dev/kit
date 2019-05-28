package coap

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/kit/net"
)

// Pool of CoAP connections.
type Pool struct {
	connections sync.Map
	create      PoolFunc
}

// PoolFunc is triggered on a miss by GetOrCreate,
// so that it may add the missing connection to the pool.
type PoolFunc func(ctx context.Context, p *Pool, a net.Addr) error

// NewPool creates a pool with a connection factory function.
func NewPool(create PoolFunc) *Pool {
	return &Pool{create: create}
}

// Put adds a connection to the pool.
func (p *Pool) Put(a net.Addr, c *coap.ClientConn) {
	p.connections.Store(a.String(), c)
}

// Delete deletes a connection from the pool.
// It does not close the connection.
func (p *Pool) Delete(a net.Addr) {
	p.connections.Delete(a.String())
}

// Get retrieves a connection from the pool.
func (p *Pool) Get(a net.Addr) (c *coap.ClientConn, ok bool) {
	v, ok := p.connections.Load(a.String())
	if ok {
		c = v.(*coap.ClientConn)
	}
	return
}

// GetOrCreate returns the cached connection or calls create otherwise.
func (p *Pool) GetOrCreate(ctx context.Context, a net.Addr) (_ *coap.ClientConn, err error) {
	if c, ok := p.Get(a); ok {
		return c, nil
	}
	err = p.create(ctx, p, a)
	if err != nil {
		return
	}
	if c, ok := p.Get(a); ok {
		return c, nil
	}
	err = fmt.Errorf("no connection to %s", a.String())
	return
}
