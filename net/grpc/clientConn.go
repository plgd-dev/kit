package grpc

import (
	"fmt"

	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type clientConnOptions struct {
	tlsConfig          security.TLSConfig
	secure             bool
	insecure           bool
	insecureSkipVerify bool
}

// ClientConnOption configures how we set up the connection.
type ClientConnOption interface {
	applyOnClientConn(*clientConnOptions)
}

// Option configures how we set up the server or the connection.
type Option interface {
	ClientConnOption
	ServerOption
}

type withTLSOption struct {
	tlsConfig security.TLSConfig
}

func (o withTLSOption) applyOnClientConn(opts *clientConnOptions) {
	opts.tlsConfig = o.tlsConfig
	opts.secure = true
}

// WithTLS creates connection with TLS.
func WithTLS(tlsConfig security.TLSConfig) Option {
	return &withTLSOption{tlsConfig}
}

type withInsecureSkipVerify struct {
}

func (o withInsecureSkipVerify) applyOnClientConn(opts *clientConnOptions) {
	opts.insecureSkipVerify = true
}

// WithInsecureSkipVerify without verifies peer
func WithInsecureSkipVerify() ClientConnOption {
	return &withInsecureSkipVerify{}
}

type withInsecureConfigOption struct {
}

func (o withInsecureConfigOption) applyOnClientConn(opts *clientConnOptions) {
	opts.insecure = true
}

// WithInsecure returns a NewClientConn which disables transport security for this ClientConn. Note that transport security is required unless WithInsecure is set.
func WithInsecure() Option {
	return &withInsecureConfigOption{}
}

// NewClientConnWithOptions creates grpc client connection. One of WithTLS, WithInsecure must be set.
func NewClientConnWithOptions(host string, opts ...ClientConnOption) (conn *grpc.ClientConn, err error) {
	var cfg clientConnOptions
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

// NewClientConn creates gRPC client connection
// based on the generated flag security.IsInsecure().
func NewClientConn(host string, tls *security.TLSConfig) (*grpc.ClientConn, error) {
	if host == "" {
		return nil, status.Errorf(codes.InvalidArgument, "missing gRPC server address")
	}
	if tls == nil && !security.IsInsecure() {
		return nil, status.Errorf(codes.InvalidArgument, "missing TLS config")
	}

	var opt Option
	if security.IsInsecure() {
		opt = WithInsecure()
	} else {
		opt = WithTLS(*tls)
	}

	conn, err := NewClientConnWithOptions(host, opt)
	if err != nil {
		return nil, fmt.Errorf("could not create gRPC client: %v", err)
	}
	return conn, nil
}
