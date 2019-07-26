package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"

	"github.com/go-ocf/kit/security/jwt"
)

type AuthInterceptors struct {
	authFunc grpc_auth.AuthFunc
}

func MakeAuthInterceptors(authFunc grpc_auth.AuthFunc) AuthInterceptors {
	return AuthInterceptors{authFunc: authFunc}
}

func MakeJWTInterceptors(jwksUrl string, claims ClaimsFunc) AuthInterceptors {
	return MakeAuthInterceptors(ValidateJWT(jwksUrl, claims))
}

func (f AuthInterceptors) Unary() grpc.ServerOption {
	return grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(f.authFunc))
}
func (f AuthInterceptors) Stream() grpc.ServerOption {
	return grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(f.authFunc))
}

type ClaimsFunc = func(context.Context) Claims
type Claims = interface{ Valid() error }

func ValidateJWT(jwksUrl string, claims ClaimsFunc) grpc_auth.AuthFunc {
	validator := jwt.NewValidator(jwksUrl)
	return func(ctx context.Context) (context.Context, error) {
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
