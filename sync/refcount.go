package sync

import (
	"context"
	"fmt"
	"sync/atomic"
)

type ReleaseDataFunc = func(ctx context.Context, data interface{}) error

type RefCounter struct {
	count           int64
	data            interface{}
	releaseDataFunc ReleaseDataFunc
}

// Data returns data
func (r *RefCounter) Data() (interface{}, error) {
	v := atomic.LoadInt64(&r.count)
	if v <= 0 || r.data == nil {
		return nil, fmt.Errorf("using RefCounterer after data released")
	}
	return r.data, nil
}

// Increment increments counter
func (r *RefCounter) Increment() error {
	v := atomic.AddInt64(&r.count, 1)
	if v <= 1 || r.data == nil {
		return fmt.Errorf("using RefCounterer after data released")
	}

	return nil
}

// Decrement decrements counter, when counter reach 0, releaseDataFunc will be called
func (r *RefCounter) Decrement(ctx context.Context) error {
	v := atomic.AddInt64(&r.count, -1)
	if v < 0 || r.data == nil {
		return fmt.Errorf("using RefCounterer after data released")
	}
	if v == 0 {
		data := r.data
		r.data = nil
		if r.releaseDataFunc != nil {
			return r.releaseDataFunc(ctx, data)
		}
	}
	return nil
}

// NewRefCounter creates RefCounterer
func NewRefCounter(data interface{}, releaseDataFunc ReleaseDataFunc) *RefCounter {
	return &RefCounter{
		data:            data,
		count:           1,
		releaseDataFunc: releaseDataFunc,
	}
}
