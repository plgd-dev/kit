package grpc

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// WithOutTLS dial without tls
func WithOutTLS() grpc.DialOption {
	return grpc.WithInsecure()
}

// WithTLS dial with tls
func WithTLS(config *security.TLSConfig) (grpc.DialOption, error) {
	cert, err := tls.LoadX509KeyPair(config.Certificate, config.CertificateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot load x509 certificate('%v', '%v'): %v", config.Certificate, config.CertificateKey, err)
	}
	ca, err := security.LoadX509(config.CAPool)
	if err != nil {
		return nil, fmt.Errorf("cannot load x509 certificate authorities('%v'): %v", config.CAPool, err)
	}
	pool := security.NewDefaultCertPool(ca)

	return grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	})), nil
}

// NewClientConn creates gRPC client connection
// based on the generated flag security.IsInsecure().
// DEPRECATED - use grpc.Dial with options WithTLS, WithOutTLS!!!
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
