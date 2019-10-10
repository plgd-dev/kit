package grpc

import (
	"context"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
)

type Interceptor = func(ctx context.Context, method string) (context.Context, error)

func UnaryServerInterceptor(intercept Interceptor) grpc.ServerOption {
	return grpc.UnaryInterceptor(
		func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			newCtx, err := intercept(ctx, info.FullMethod)
			if err != nil {
				return nil, err
			}
			return handler(newCtx, req)
		})
}

func StreamServerInterceptor(intercept Interceptor) grpc.ServerOption {
	return grpc.StreamInterceptor(
		func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			newCtx, err := intercept(stream.Context(), info.FullMethod)
			if err != nil {
				return err
			}
			wrapped := grpc_middleware.WrapServerStream(stream)
			wrapped.WrappedContext = newCtx
			return handler(srv, wrapped)
		})
}
