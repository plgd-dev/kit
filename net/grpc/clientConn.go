package grpc

import (
	"fmt"

	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// NewClientConn creates gRPC client connection
// based on the generated flag security.IsInsecure().
func NewClientConn(host string, tls *security.TLSConfig) (*grpc.ClientConn, error) {
	if host == "" {
		return nil, status.Errorf(codes.InvalidArgument, "missing gRPC server address")
	}
	if tls == nil && !security.IsInsecure() {
		return nil, status.Errorf(codes.InvalidArgument, "missing TLS config")
	}

	var opts []grpc.DialOption
	if security.IsInsecure() {
		opts = append(opts, grpc.WithInsecure())
	} else {
		tlsCfg, err := security.NewTLSConfigFromConfiguration(*tls, security.VerifyServerCertificate)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid TLS config: %v", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	conn, err := grpc.Dial(host, opts...)
	if err != nil {
		return nil, fmt.Errorf("could not create gRPC client: %v", err)
	}
	return conn, nil
}
