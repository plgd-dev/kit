package http

import (
	"github.com/valyala/fasthttp"
)

// RequestCtx provides http methods: POST.
// It is used to send a single request and obtain the response.
type RequestCtx struct {
	Req  *fasthttp.Request
	Resp *fasthttp.Response
}

// AcquireRequestCtx along with ReleaseRequestCtx are used to
// manage the lifetime of the enclosed pooled data structures.
func AcquireRequestCtx() *RequestCtx {
	return &RequestCtx{
		Req:  fasthttp.AcquireRequest(),
		Resp: fasthttp.AcquireResponse(),
	}
}

// ReleaseRequestCtx to release content. Be careful: you must copy all slices
// like body/headers that you want to use after ReleaseRequestCtx. Because
// they will be overridden by next AcquireRequestCtx.
func ReleaseRequestCtx(ctx *RequestCtx) {
	fasthttp.ReleaseRequest(ctx.Req)
	fasthttp.ReleaseResponse(ctx.Resp)
}

// PostProto posts a protobuf message to an HTTP server and
// receives a protobuf response on fasthttp.StatusOK.
func (ctx *RequestCtx) PostProto(client *fasthttp.Client, uri string, in ProtoMarshaler, out ProtoUnmarshaler) (int, error) {
	ctx.Req.SetRequestURI(uri)
	ctx.Req.Header.SetMethod("POST")
	if err := WriteRequest(in, ctx.Req); err != nil {
		return -1, err
	}
	if err := client.Do(ctx.Req, ctx.Resp); err != nil {
		return -1, err
	}
	code := ctx.Resp.StatusCode()
	if code != fasthttp.StatusOK {
		return code, ReadErrorResponse(ctx.Resp)
	}
	if err := ReadResponse(out, ctx.Resp); err != nil {
		return code, err
	}
	return code, nil
}
