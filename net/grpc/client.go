package grpc

import (
	"fmt"

	"github.com/go-ocf/kit/net"
	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewClientConn(addr string, tls *security.TLSConfig) (*grpc.ClientConn, error) {
	if addr == "" {
		return nil, status.Errorf(codes.InvalidArgument, "missing gRPC server address")
	}
	if tls == nil && !security.IsInsecure() {
		return nil, status.Errorf(codes.InvalidArgument, "missing TLS config")
	}

	var opt net.GrpcOption
	if security.IsInsecure() {
		opt = net.WithInsecure()
	} else {
		opt = net.WithTLS(*tls)
	}

	conn, err := net.NewGrpcClientConn(addr, opt)
	if err != nil {
		return nil, fmt.Errorf("could not create gRPC client: %v", err)
	}
	return conn, nil
}
