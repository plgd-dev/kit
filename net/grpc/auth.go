package grpc

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"

	"github.com/go-ocf/kit/security/jwt"
)

type AuthInterceptors struct {
	authFunc Interceptor
}

func MakeAuthInterceptors(authFunc Interceptor, whiteListedMethods ...string) AuthInterceptors {
	return AuthInterceptors{
		authFunc: func(ctx context.Context, method string) (context.Context, error) {
			for _, wa := range whiteListedMethods {
				if wa == method {
					return ctx, nil
				}
			}
			return authFunc(ctx, method)
		},
	}
}

func MakeJWTInterceptors(jwksURL string, tls *tls.Config, claims ClaimsFunc, whiteListedMethods ...string) AuthInterceptors {
	return MakeAuthInterceptors(ValidateJWT(jwksURL, tls, claims), whiteListedMethods...)
}

func (f AuthInterceptors) Unary() grpc.ServerOption {
	return UnaryServerInterceptor(f.authFunc)
}
func (f AuthInterceptors) Stream() grpc.ServerOption {
	return StreamServerInterceptor(f.authFunc)
}

type ClaimsFunc = func(ctx context.Context, method string) Claims
type Claims = interface{ Valid() error }

func ValidateJWT(jwksURL string, tls *tls.Config, claims ClaimsFunc) Interceptor {
	validator := jwt.NewValidator(jwksURL, tls)
	return func(ctx context.Context, method string) (context.Context, error) {
		token, err := grpc_auth.AuthFromMD(ctx, "bearer")
		if err != nil {
			return nil, err
		}
		err = validator.ParseWithClaims(token, claims(ctx, method))
		if err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}
		return ctx, nil
	}
}

func CtxWithToken(ctx context.Context, token string) context.Context {
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %s", "bearer", token))
	return metautils.NiceMD(md).ToOutgoing(ctx)
}

func CtxWithIncomingToken(ctx context.Context, token string) context.Context {
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %s", "bearer", token))
	return metautils.NiceMD(md).ToIncoming(ctx)
}
