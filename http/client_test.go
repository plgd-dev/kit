package http

import (
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/buaazp/fasthttprouter"
	"github.com/valyala/fasthttp"
)

const (
	strResp = "strResp"
	strReq  = "strReq"
)

func testHandler(t *testing.T, ctx *fasthttp.RequestCtx) {
	var req TestRequest
	ct := string(ctx.Request.Header.ContentType())
	if ct != ProtobufContentType(&req) {
		t.Fatalf("Unexpected content-type(%v) in req, expected %v", ct, ProtobufContentType(&req))
	}

	if err := req.Unmarshal(ctx.Request.Body()); err != nil {
		t.Fatalf("Cannot unmarshal request: %v", err)
	}

	if req.StringVal != strReq {
		t.Fatalf("Unexpected value(%v) in proto req, expected %v", req.StringVal, strReq)
	}

	resp := TestResponse{
		StringVal: strResp,
	}

	ctx.SetContentType(ProtobufContentType(&resp))
	out := make([]byte, 1024)
	var err error
	if len(out) < resp.Size() {
		out, err = resp.Marshal()
	} else {
		var l int
		l, err = resp.MarshalTo(out)
		out = out[:l]
	}

	if err != nil {
		t.Fatalf("Cannot marshal response: %v", err)
	}

	ctx.Response.SetBody(out)
}

func testCreateHTTPServer(t *testing.T) (*fasthttp.Server, string, chan error) {
	router := fasthttprouter.New()
	router.POST("/test", func(ctx *fasthttp.RequestCtx) {
		testHandler(t, ctx)
	})

	s := fasthttp.Server{
		Handler: router.Handler,
	}
	ln, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatalf("Cannot listen on server: %v", err)
	}

	fin := make(chan error)
	var wk sync.WaitGroup
	wk.Add(1)
	go func() {
		wk.Done()
		fin <- s.Serve(ln)
	}()
	wk.Wait()

	return &s, "127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), fin
}

func TestClientPost(t *testing.T) {

	s, addrstr, fin := testCreateHTTPServer(t)
	defer func() {
		s.Shutdown()
		if err := <-fin; err != nil {
			t.Fatalf("server unexcpected shutdown: %v", err)
		}
	}()

	ctx := AcquireRequestCtx()
	defer ReleaseRequestCtx(ctx)

	req := TestRequest{
		StringVal: strReq,
	}
	var resp TestResponse
	code, err := ctx.PostProto(&fasthttp.Client{}, "http://"+addrstr+"/test", &req, &resp)
	if err != nil {
		t.Fatalf("Cannot post proto: %v", err)
	}
	if code != fasthttp.StatusOK {
		t.Fatalf("Returns unexpected status code %v", code)
	}
	if resp.StringVal != strResp {
		t.Fatalf("Returns unexpected value(%v) in proto, expected %v", resp.StringVal, strResp)
	}
}
