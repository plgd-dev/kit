package grpc

import (
	"fmt"
	"net"

	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server handles gRPC requests to the service.
type Server struct {
	server   *grpc.Server
	listener net.Listener
}

// Config holds service's settings.
type Config struct {
	Addr string `envconfig:"ADDRESS" default:"0.0.0.0:9100"`

	TLSConfig security.TLSConfig
}

// NewServer instantiates the server and provides the register callback
// for registering service's protobuf definition.
func NewServer(cfg Config, register func(*grpc.Server)) (*Server, error) {
	option := makeConnectionOption(cfg.TLSConfig)
	srv, err := NewServerWithOptions(option)
	if err != nil {
		return nil, fmt.Errorf("could not create server: %v", err)
	}
	register(srv)

	lis, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listening failed: %v", err)
	}
	return &Server{server: srv, listener: lis}, nil
}

// Serve starts serving and blocks.
func (s *Server) Serve() error {
	err := s.server.Serve(s.listener)
	if err != nil {
		return fmt.Errorf("serving failed: %v", err)
	}
	return nil
}

// Stop ends serving.
func (s *Server) Stop() {
	s.server.Stop()
}

// NewServer creates grpc server. One of WithTLSConfig, WithInsecure must be set.
func NewServerWithOptions(opts ...ServerOption) (server *grpc.Server, err error) {
	var cfg serverOptions
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

func makeConnectionOption(tls security.TLSConfig) Option {
	if security.IsInsecure() {
		return WithInsecure()
	} else {
		return WithTLS(tls)
	}
}

type serverOptions struct {
	tlsConfig security.TLSConfig
	secure    bool
	insecure  bool
}

// ServerOption configures how we set up the server.
type ServerOption interface {
	applyOnServer(*serverOptions)
}

func (o withTLSOption) applyOnServer(opts *serverOptions) {
	opts.tlsConfig = o.tlsConfig
	opts.secure = true
}

func (o withInsecureConfigOption) applyOnServer(opts *serverOptions) {
	opts.insecure = true
}
