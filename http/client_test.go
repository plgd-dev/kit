package http

import (
	"errors"
	"net"
	"testing"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

const (
	strResp   = "strResp"
	strReq    = "strReq"
	badReqStr = "badReqStr"
)

func startTestHTTPServer(h fasthttp.RequestHandler) *fasthttputil.InmemoryListener {

	listener := fasthttputil.NewInmemoryListener()
	go fasthttp.Serve(listener, h)
	return listener
}

func createTestHTTPClient(ln *fasthttputil.InmemoryListener) *fasthttp.Client {
	c := fasthttp.Client{
		Dial: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
	}
	return &c
}

func testHandler(t *testing.T, ctx *fasthttp.RequestCtx) {
	var req TestRequest
	ct := string(ctx.Request.Header.ContentType())
	if ct != ProtobufContentType(&req) {
		t.Fatalf("Unexpected content-type(%v) in Req, expected %v", ct, ProtobufContentType(&req))
	}

	if err := req.Unmarshal(ctx.Request.Body()); err != nil {
		t.Fatalf("Cannot unmarshal request: %v", err)
	}

	if req.StringVal != strReq {
		WriteErrorResponse(errors.New(badReqStr), &ctx.Response)
		ctx.Response.SetStatusCode(fasthttp.StatusBadRequest)
		return
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

func testCreateHTTPServer(t *testing.T) (*fasthttputil.InmemoryListener, *fasthttp.Client) {
	server := startTestHTTPServer(func(ctx *fasthttp.RequestCtx) {
		testHandler(t, ctx)
	})
	client := createTestHTTPClient(server)
	return server, client
}

func TestRequestCtx_PostProto(t *testing.T) {
	server, client := testCreateHTTPServer(t)
	defer server.Close()

	type args struct {
		in  ProtoMarshaler
		out ProtoUnmarshaler
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				in: &TestRequest{
					StringVal: strReq,
				},
				out: &TestResponse{},
			},
			want: fasthttp.StatusOK,
		},
		{
			name: "invalid",
			args: args{
				in: &TestRequest{
					StringVal: badReqStr,
				},
				out: &TestResponse{},
			},
			want:    fasthttp.StatusBadRequest,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := AcquireRequestCtx()
			defer ReleaseRequestCtx(ctx)

			got, err := ctx.PostProto(client, "http://localhost", tt.args.in, tt.args.out)
			if (err != nil) != tt.wantErr {
				t.Errorf("RequestCtx.PostProto() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RequestCtx.PostProto() = %v, want %v", got, tt.want)
			}
		})
	}
}
