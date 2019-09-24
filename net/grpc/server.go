package grpc

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server handles gRPC requests to the service.
type Server struct {
	*grpc.Server
	listener net.Listener
}

// Config holds service's settings.
type Config struct {
	Addr string `envconfig:"ADDRESS" default:"0.0.0.0:9100"`

	TLSConfig security.TLSConfig
}

// NewServer instantiates a gRPC server.
func NewServer(cfg Config, opt ...grpc.ServerOption) (*Server, error) {
	tls, err := tlsCreds(cfg.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %v", err)
	}
	opt = append(opt, tls)

	lis, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listening failed: %v", err)
	}

	srv := grpc.NewServer(opt...)
	return &Server{Server: srv, listener: lis}, nil
}

// NewServerWithoutPeerVerification instantiates a gRPC server without peer verification.
func NewServerWithoutPeerVerification(cfg Config, opt ...grpc.ServerOption) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSConfig.Certificate, cfg.TLSConfig.CertificateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot load x509 key pair('%v', '%v'): %v", cfg.TLSConfig.Certificate, cfg.TLSConfig.CertificateKey, err)
	}
	opt = append(opt, grpc.Creds(credentials.NewTLS(security.NewTLSConfigWithoutPeerVerification(cert))))

	lis, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listening failed: %v", err)
	}

	srv := grpc.NewServer(opt...)
	return &Server{Server: srv, listener: lis}, nil
}

// Serve starts serving and blocks.
func (s *Server) Serve() error {
	err := s.Server.Serve(s.listener)
	if err != nil {
		return fmt.Errorf("serving failed: %v", err)
	}
	return nil
}

func tlsCreds(cfg security.TLSConfig) (grpc.ServerOption, error) {
	tlsConfig, err := security.NewTLSConfigFromConfiguration(cfg, security.VerifyClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("cannot create grpc connection: %v", err)
	}
	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}
