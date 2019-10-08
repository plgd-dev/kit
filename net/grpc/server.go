package grpc

import (
	"crypto/tls"
	"fmt"
	"net"

	"google.golang.org/grpc"
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
	Addr string `envconfig:"ADDRESS" default:"0.0.0.0:9100"`
}

// NewServer instantiates a gRPC server.
func NewServer(addr string, opts ...grpc.ServerOption) (*Server, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening failed: %v", err)
	}

	srv := grpc.NewServer(opts...)
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

// Close stops the gRPC server. It immediately closes all open
// connections and listeners.
// It cancels all active RPCs on the server side and the corresponding
// pending RPCs on the client side will get notified by connection
// errors.
func (s *Server) Close() {
	s.Server.Stop()
}
