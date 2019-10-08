package grpc

import (
	"context"
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

func MakeAuthInterceptors(authFunc Interceptor) AuthInterceptors {
	return AuthInterceptors{authFunc: authFunc}
}

func MakeJWTInterceptors(jwksUrl string, claims ClaimsFunc) AuthInterceptors {
	return MakeAuthInterceptors(ValidateJWT(jwksUrl, claims))
}

func (f AuthInterceptors) Unary() grpc.ServerOption {
	return UnaryServerInterceptor(f.authFunc)
}
func (f AuthInterceptors) Stream() grpc.ServerOption {
	return StreamServerInterceptor(f.authFunc)
}

type ClaimsFunc = func(context.Context) Claims
type Claims = interface{ Valid() error }

func ValidateJWT(jwksUrl string, claims ClaimsFunc) Interceptor {
	validator := jwt.NewValidator(jwksUrl)
	return func(ctx context.Context, method string) (context.Context, error) {
		token, err := grpc_auth.AuthFromMD(ctx, "bearer")
		if err != nil {
			return nil, err
		}
		err = validator.ParseWithClaims(token, claims(ctx))
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
