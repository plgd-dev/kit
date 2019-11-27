package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/go-ocf/kit/security/jwt"
)

type Interceptor = func(ctx context.Context, method, uri string) (context.Context, error)
type AuthArgs struct{ Scope string }

func NewInterceptor(jwksUrl string, tls tls.Config, auths map[string]map[string]AuthArgs) Interceptor {
	return ValidateJWT(jwksUrl, tls, MakeClaimsFunc(auths))
}

func MakeClaimsFunc(methods map[string]map[string]AuthArgs) ClaimsFunc {
	return func(ctx context.Context, method, uri string) Claims {
		uris, ok := methods[method]
		if !ok {
			return &DeniedClaims{fmt.Errorf("inaccessible method: %v", method)}
		}
		arg, ok := uris[uri]
		if !ok {
			return &DeniedClaims{fmt.Errorf("inaccessible uri: %v %v", method, uri)}
		}
		return jwt.NewScopeClaims(arg.Scope)
	}
}

type DeniedClaims struct {
	Err error
}

func (c DeniedClaims) Valid() error {
	return c.Err
}