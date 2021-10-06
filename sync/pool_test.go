package sync_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/plgd-dev/kit/v2/net"
	"github.com/plgd-dev/kit/v2/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPutGet(t *testing.T) {
	p := sync.NewPool()
	p.Put(testAddr, &testConn)

	c, ok := p.Get(testAddr)
	require.True(t, ok)
	assert.True(t, &testConn == c)
}

func TestDelete(t *testing.T) {
	p := sync.NewPool()
	p.Put(testAddr, &testConn)
	c, ok := p.Delete(testAddr)
	assert.True(t, ok)
	assert.Equal(t, c, &testConn)

	_, ok = p.Get(testAddr)
	assert.False(t, ok)
}

func TestMiss(t *testing.T) {
	p := sync.NewPool()

	_, ok := p.Get(testAddr)
	assert.False(t, ok)
}

func TestCreated(t *testing.T) {
	p := sync.NewPool()
	p.SetFactory(func(ctx context.Context, key string) (interface{}, error) {
		assert.Equal(t, testAddr, key)
		return &testConn, nil
	})

	c, err := p.GetOrCreate(context.Background(), testAddr)
	require.NoError(t, err)
	assert.True(t, &testConn == c)
}

func TestCreationNotNeeded(t *testing.T) {
	p := sync.NewPool()
	p.Put(testAddr, &testConn)

	c, err := p.GetOrCreate(context.Background(), testAddr)
	require.NoError(t, err)
	assert.True(t, &testConn == c)
}

func TestCreationFailure(t *testing.T) {
	p := sync.NewPool()
	p.SetFactory(func(ctx context.Context, key string) (interface{}, error) {
		return nil, fmt.Errorf("")
	})

	_, err := p.GetOrCreate(context.Background(), testAddr)
	assert.Error(t, err)
}

func TestMissingFactory(t *testing.T) {
	p := sync.NewPool()

	_, err := p.GetOrCreate(context.Background(), testAddr)
	assert.Error(t, err)
}

var (
	testAddr = net.MakeAddr("http", "host", 42).String()
	testConn = "textConn"
)
