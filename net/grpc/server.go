package grpc

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/go-ocf/kit/security/acme"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ServerCertManager = interface {
	GetServerTLSConfig() tls.Config
}

// Server handles gRPC requests to the service.
type Server struct {
	*grpc.Server
	listener    net.Listener
	certManager ServerCertManager
}

// Config holds service's settings.
type Config struct {
	Addr       string      `envconfig:"ADDRESS" default:"0.0.0.0:9100"`
	AcmeConfig acme.Config `envconfig:"ACME_SERVER"`
}

// NewServer instantiates a gRPC server.
func NewServer(addr string, certManager ServerCertManager, opt ...grpc.ServerOption) (*Server, error) {
	tlsCfg := certManager.GetServerTLSConfig()

	opts := make([]grpc.ServerOption, 0, len(opt))
	opts = append(opts, grpc.Creds(credentials.NewTLS(&tlsCfg)))
	opts = append(opts, opt...)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening failed: %v", err)
	}

	srv := grpc.NewServer(opts...)
	return &Server{Server: srv, listener: lis, certManager: certManager}, nil
}

// NewServer instantiates a gRPC server.
func NewServerWithConfig(cfg Config, opt ...grpc.ServerOption) (*Server, error) {
	certManager, err := acme.NewCertManagerFromConfiguration(cfg.AcmeConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %v", err)
	}
	return NewServer(cfg.Addr, certManager, opt...)
}

// NewServerWithoutPeerVerification instantiates a gRPC server without peer verification.
func NewServerWithConfigWithoutPeerVerification(cfg Config, opt ...grpc.ServerOption) (*Server, error) {
	certManager, err := acme.NewCertManagerFromConfiguration(cfg.AcmeConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %v", err)
	}

	tlsCfg := certManager.GetServerTLSConfig()
	tlsCfg.ClientAuth = tls.NoClientCert
	tlsCfg.ClientCAs = nil
	opts := make([]grpc.ServerOption, 0, len(opt))
	opts = append(opts, grpc.Creds(credentials.NewTLS(&tlsCfg)))
	opts = append(opts, opt...)

	lis, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listening failed: %v", err)
	}

	srv := grpc.NewServer(opts...)
	return &Server{Server: srv, listener: lis, certManager: certManager}, nil
}

// Serve starts serving and blocks.
func (s *Server) Serve() error {
	err := s.Server.Serve(s.listener)
	if err != nil {
		return fmt.Errorf("serving failed: %v", err)
	}
	return nil
}
