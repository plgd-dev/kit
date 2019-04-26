package net

import (
	"fmt"

	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type grpcServerOptions struct {
	tlsConfig security.TLSConfig
	secure    bool
	insecure  bool
}

// GrpcServerOption configures how we set up the server.
type GrpcServerOption interface {
	applyOnServer(*grpcServerOptions)
}

func (o withTLSOption) applyOnServer(opts *grpcServerOptions) {
	opts.tlsConfig = o.tlsConfig
	opts.secure = true
}

func (o withInsecureConfigOption) applyOnServer(opts *grpcServerOptions) {
	opts.insecure = true
}

// NewGrpcServer creates grpc server. One of WithTLSConfig, WithInsecure must be set.
func NewGrpcServer(opts ...GrpcServerOption) (server *grpc.Server, err error) {
	var cfg grpcServerOptions
	for _, o := range opts {
		o.applyOnServer(&cfg)
	}
	if !cfg.secure && !cfg.insecure {
		return nil, fmt.Errorf("cannot create grpc server: cannot use transport layer: not set - use WithTLSConfig or WithInsecure option")
	}
	if cfg.secure && cfg.insecure {
		return nil, fmt.Errorf("cannot create grpc server: cannot use transport layer: both WithTLSConfig and WithInsecure are set")
	}

	if !cfg.secure {
		return grpc.NewServer(), nil
	}
	serverCertVerifier, err := security.NewClientCertificateVerifier()
	if err != nil {
		return nil, fmt.Errorf("cannot create grpc connection: %v", err)
	}
	tlsConfig, err := security.SetTLSConfig(cfg.tlsConfig, serverCertVerifier)
	if err != nil {
		return nil, fmt.Errorf("cannot create grpc connection: %v", err)
	}
	return grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig))), nil
}
