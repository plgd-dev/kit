package sync

import (
	"context"
	"sync"
)

// Pool is a synchronized key-value store with customizable factory for missing items.
type Pool struct {
	mtx    sync.Mutex
	store  map[string]interface{}
	create PoolFunc
}

// PoolFunc is triggered on a miss by GetOrCreate,
// so that it may add the missing item to the pool.
type PoolFunc func(ctx context.Context, key string) (interface{}, error)

// NewPool creates a pool with the create factory function.
func NewPool(create PoolFunc) *Pool {
	return &Pool{
		store:  make(map[string]interface{}),
		create: create,
	}
}

// Put adds an item to the pool.
func (p *Pool) Put(key string, item interface{}) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.store[key] = item
}

// Delete deletes an item from the pool.
func (p *Pool) Delete(key string) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	delete(p.store, key)
}

// Get returns an item from the pool or false.
func (p *Pool) Get(key string) (_ interface{}, ok bool) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	item, ok := p.store[key]
	return item, ok
}

// GetOrCreate returns an item and calls create on a mis.
// Warning: The create function is called under the lock,
// therefore it must not call any Pool's methods to avoid deadlocks.
func (p *Pool) GetOrCreate(ctx context.Context, key string) (interface{}, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if item, ok := p.store[key]; ok {
		return item, nil
	}
	item, err := p.create(ctx, key)
	if err != nil {
		return nil, err
	}
	p.store[key] = item
	return item, nil
}
