package grpc

import (
	"fmt"
	"net"

	kit "github.com/go-ocf/kit/net"
	"github.com/go-ocf/kit/security"
	"google.golang.org/grpc"
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
	srv, err := kit.NewGrpcServer(option)
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

func makeConnectionOption(tls security.TLSConfig) kit.GrpcOption {
	if security.IsInsecure() {
		return kit.WithInsecure()
	} else {
		return kit.WithTLS(tls)
	}
}
