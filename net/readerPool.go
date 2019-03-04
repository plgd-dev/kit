package net

import (
	"bufio"
	"io"
	"sync"
)

var readerPool sync.Pool

func acquireReader(rd io.Reader) *bufio.Reader {
	v := readerPool.Get()
	if v == nil {
		return bufio.NewReaderSize(rd, 1500)
	}
	r := v.(*bufio.Reader)
	r.Reset(rd)
	return r
}

func releaseReader(r *bufio.Reader) {
	readerPool.Put(r)
}
