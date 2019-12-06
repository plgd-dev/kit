package http

import(
	coapStatus "github.com/go-ocf/kit/net/coap/status"
	grpcStatus "google.golang.org/grpc/status"
	"github.com/go-ocf/kit/coapconv"
	"github.com/go-ocf/kit/grpcconv"
	netHttp "net/http"
)

type grpcErr interface {
	GRPCStatus() *grpcStatus.Status
}

// ErrToStatusWithDef converts err with default http.Status(for unknown conversion) to http.Status.
func ErrToStatusWithDef(err error, def int) int {
	if err == nil {
		return netHttp.StatusOK
	}
	switch e := err.(type) {
	case coapStatus.Status:
		return coapconv.ToHTTPCode(e.Message().Code(), def)
	case grpcErr:
		return grpcconv.ToHTTPCode(e.GRPCStatus().Code(), def)
	}
	return def
}

// ErrToStatus converts err to http.Status.
func ErrToStatus(err error) int {
	return ErrToStatusWithDef(err, netHttp.StatusInternalServerError)
}
