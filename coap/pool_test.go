package coap_test

import (
	"context"
	"fmt"
	"testing"

	gocoap "github.com/go-ocf/go-coap"
	"github.com/go-ocf/kit/coap"
	"github.com/go-ocf/kit/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPutGet(t *testing.T) {
	p := coap.NewPool(failingCreate(t))
	p.Put(testAddr, &testConn)

	c, ok := p.Get(testAddr)
	require.True(t, ok)
	assert.True(t, &testConn == c)
}

func TestDelete(t *testing.T) {
	p := coap.NewPool(failingCreate(t))
	p.Put(testAddr, &testConn)
	p.Delete(testAddr)

	_, ok := p.Get(testAddr)
	assert.False(t, ok)
}

func TestMiss(t *testing.T) {
	p := coap.NewPool(failingCreate(t))

	_, ok := p.Get(testAddr)
	assert.False(t, ok)
}

func TestCreated(t *testing.T) {
	create := func(ctx context.Context, p *coap.Pool, a net.Addr) error {
		assert.Equal(t, testAddr, a)
		p.Put(testAddr, &testConn)
		return nil
	}
	p := coap.NewPool(create)

	c, err := p.GetOrCreate(context.Background(), testAddr)
	require.NoError(t, err)
	assert.True(t, &testConn == c)
}

func TestCreationNotNeeded(t *testing.T) {
	p := coap.NewPool(failingCreate(t))
	p.Put(testAddr, &testConn)

	c, err := p.GetOrCreate(context.Background(), testAddr)
	require.NoError(t, err)
	assert.True(t, &testConn == c)
}

func TestCreationFailure(t *testing.T) {
	create := func(ctx context.Context, p *coap.Pool, a net.Addr) error {
		return fmt.Errorf("")
	}
	p := coap.NewPool(create)

	_, err := p.GetOrCreate(context.Background(), testAddr)
	assert.Error(t, err)
}

func TestMissAfterCreate(t *testing.T) {
	create := func(ctx context.Context, p *coap.Pool, a net.Addr) error {
		return nil
	}
	p := coap.NewPool(create)

	_, err := p.GetOrCreate(context.Background(), testAddr)
	assert.Error(t, err)
}

var (
	testAddr = net.MakeAddr("host", 42)
	testConn = gocoap.ClientConn{}
)

func failingCreate(t *testing.T) coap.PoolFunc {
	return func(ctx context.Context, p *coap.Pool, a net.Addr) error {
		require.Fail(t, "unexpected create call")
		return nil
	}
}
