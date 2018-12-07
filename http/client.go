package http

import (
	"github.com/valyala/fasthttp"
)

// RequestCtx provides http methods: POST.
// It is used to send a single request and obtain the response.
type RequestCtx struct {
	req  *fasthttp.Request
	resp *fasthttp.Response
}

// AcquireRequestCtx along with ReleaseRequestCtx are used to
// manage the lifetime of the enclosed pooled data structures.
func AcquireRequestCtx() *RequestCtx {
	return &RequestCtx{
		req:  fasthttp.AcquireRequest(),
		resp: fasthttp.AcquireResponse(),
	}
}

// ReleaseRequestCtx to release content. Be careful: you must copy all slices
// like body/headers that you want to use after ReleaseRequestCtx. Because
// they will be overridden by next AcquireRequestCtx.
func ReleaseRequestCtx(ctx *RequestCtx) {
	fasthttp.ReleaseRequest(ctx.req)
	fasthttp.ReleaseResponse(ctx.resp)
}

// PostProto posts a protobuf message to an HTTP server and
// receives a protobuf response on fasthttp.StatusOK.
func (ctx *RequestCtx) PostProto(client *fasthttp.Client, uri string, in ProtoMarshaler, out ProtoUnmarshaler) (int, error) {
	ctx.req.SetRequestURI(uri)
	ctx.req.Header.SetMethod("POST")
	if err := WriteRequest(in, ctx.req); err != nil {
		return -1, err
	}
	if err := client.Do(ctx.req, ctx.resp); err != nil {
		return -1, err
	}
	code := ctx.resp.StatusCode()
	if code != fasthttp.StatusOK {
		return code, nil
	}
	if err := ReadResponse(out, ctx.resp); err != nil {
		return code, err
	}
	return code, nil
}
