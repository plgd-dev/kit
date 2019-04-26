package net

import (
	"fmt"

	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type grpcClientConnOptions struct {
	tlsConfig          security.TLSConfig
	secure             bool
	insecure           bool
	insecureSkipVerify bool
}

// GrpcClientConnOption configures how we set up the connection.
type GrpcClientConnOption interface {
	applyOnClientConn(*grpcClientConnOptions)
}

// GrpcOption configures how we set up the server or the connection.
type GrpcOption interface {
	GrpcClientConnOption
	GrpcServerOption
}

type withTLSOption struct {
	tlsConfig security.TLSConfig
}

func (o withTLSOption) applyOnClientConn(opts *grpcClientConnOptions) {
	opts.tlsConfig = o.tlsConfig
	opts.secure = true
}

// WithTLS creates connection with TLS.
func WithTLS(tlsConfig security.TLSConfig) GrpcOption {
	return &withTLSOption{tlsConfig}
}

type withInsecureSkipVerify struct {
}

func (o withInsecureSkipVerify) applyOnClientConn(opts *grpcClientConnOptions) {
	opts.insecureSkipVerify = true
}

// WithInsecureSkipVerify without verifies peer
func WithInsecureSkipVerify() GrpcClientConnOption {
	return &withInsecureSkipVerify{}
}

type withInsecureConfigOption struct {
}

func (o withInsecureConfigOption) applyOnClientConn(opts *grpcClientConnOptions) {
	opts.insecure = true
}

// WithInsecure returns a NewGrpcClientConn which disables transport security for this ClientConn. Note that transport security is required unless WithInsecure is set.
func WithInsecure() GrpcOption {
	return &withInsecureConfigOption{}
}

// NewGrpcClientConn creates grpc client connection. One of WithTLS, WithInsecure must be set.
func NewGrpcClientConn(host string, opts ...GrpcClientConnOption) (conn *grpc.ClientConn, err error) {
	var cfg grpcClientConnOptions
	for _, o := range opts {
		o.applyOnClientConn(&cfg)
	}
	if !cfg.secure && !cfg.insecure {
		return nil, fmt.Errorf("cannot use transport layer: not set - use WithTLS or WithInsecure option")
	}
	if cfg.secure && cfg.insecure {
		return nil, fmt.Errorf("cannot use transport layer: both WithTLS and WithInsecure are set")
	}

	if cfg.secure {
		serverCertVerifier, err := security.NewServerCertificateVerifier()
		if err != nil {
			return nil, fmt.Errorf("cannot create grpc connection: %v", err)
		}
		tlsConfig, err := security.SetTLSConfig(cfg.tlsConfig, serverCertVerifier)
		if err != nil {
			return nil, fmt.Errorf("cannot create grpc connection: %v", err)
		}
		tlsConfig.InsecureSkipVerify = cfg.insecureSkipVerify
		conn, err = grpc.Dial(host, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		conn, err = grpc.Dial(host, grpc.WithInsecure())
	}
	if err != nil {
		return nil, fmt.Errorf("cannot create grpc connection: %v", err)
	}
	return
}
