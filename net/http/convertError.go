package http

import (
	"errors"
	"github.com/go-ocf/kit/coapconv"
	"github.com/go-ocf/kit/grpcconv"
	coapStatus "github.com/go-ocf/kit/net/coap/status"
	grpcStatus "google.golang.org/grpc/status"
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
	var coapStatus coapStatus.Status
	if errors.As(err, &coapStatus) {
		return coapconv.ToHTTPCode(coapStatus.Message().Code(), def)
	}
	var grpcErr grpcErr
	if errors.As(err, &grpcErr) {
		return grpcconv.ToHTTPCode(grpcErr.GRPCStatus().Code(), def)
	}
	return def
}

// ErrToStatus converts err to http.Status.
func ErrToStatus(err error) int {
	return ErrToStatusWithDef(err, netHttp.StatusInternalServerError)
}
