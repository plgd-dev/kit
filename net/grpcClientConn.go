package net

import (
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type grpcClientConnOptions struct {
	tlsConfig *tls.Config
	insecure  bool
}

// GrpcClientConnOption configures how we set up the connection.
type GrpcClientConnOption interface {
	apply(*grpcClientConnOptions)
}

type withTLSOption struct {
	tlsConfig *tls.Config
}

func (o withTLSOption) apply(opts *grpcClientConnOptions) {
	opts.tlsConfig = o.tlsConfig
}

// WithTLS creates connection with TLS.
func WithTLS(tlsConfig *tls.Config) GrpcClientConnOption {
	return &withTLSOption{tlsConfig}
}

type withInsecureConfigOption struct {
}

func (o withInsecureConfigOption) apply(opts *grpcClientConnOptions) {
	opts.insecure = true
}

// WithInsecure returns a NewGrpcClientConn which disables transport security for this ClientConn. Note that transport security is required unless WithInsecure is set.
func WithInsecure() GrpcClientConnOption {
	return &withInsecureConfigOption{}
}

// NewGrpcClientConn creates grpc client connection. Empty tlsConfig creates insecure connection.
func NewGrpcClientConn(host string, opts ...GrpcClientConnOption) (conn *grpc.ClientConn, err error) {
	var cfg grpcClientConnOptions
	for _, o := range opts {
		o.apply(&cfg)
	}
	if cfg.tlsConfig != nil && cfg.insecure {
		return nil, fmt.Errorf("cannot use WithTLS and WithInsecure in same time")
	}

	if cfg.tlsConfig != nil {
		conn, err = grpc.Dial(host, grpc.WithTransportCredentials(credentials.NewTLS(cfg.tlsConfig)))
	} else if cfg.insecure {
		conn, err = grpc.Dial(host, grpc.WithInsecure())
	} else {
		conn, err = grpc.Dial(host)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot create grpc connection: %v", err)
	}
	return
}
