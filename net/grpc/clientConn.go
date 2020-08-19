package grpc

import (
	"fmt"

	"github.com/plgd-dev/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// NewClientConn creates gRPC client connection
func NewClientConn(host string, tls security.TLSConfig, opt ...grpc.DialOption) (*grpc.ClientConn, error) {
	if host == "" {
		return nil, status.Errorf(codes.InvalidArgument, "missing gRPC server address")
	}

	var opts []grpc.DialOption
	tlsCfg, err := security.NewTLSConfigFromConfiguration(tls, security.VerifyServerCertificate)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid TLS config: %v", err)
	}
	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	opts = append(opts, opt...)

	conn, err := grpc.Dial(host, opts...)
	if err != nil {
		return nil, fmt.Errorf("could not create gRPC client: %w", err)
	}
	return conn, nil
}
