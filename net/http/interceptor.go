package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/go-ocf/kit/security/jwt"
	"regexp"
)

type Interceptor = func(ctx context.Context, method, uri string) (context.Context, error)

type AuthArgs struct {
	URI    *regexp.Regexp
	Scopes []*regexp.Regexp
}

func NewInterceptor(jwksUrl string, tls tls.Config, auths map[string][]AuthArgs) Interceptor {
	return ValidateJWT(jwksUrl, tls, MakeClaimsFunc(auths))
}

func MakeClaimsFunc(methods map[string][]AuthArgs) ClaimsFunc {
	return func(ctx context.Context, method, uri string) Claims {
		args, ok := methods[method]
		if !ok {
			return &DeniedClaims{fmt.Errorf("inaccessible method: %v", method)}
		}
		for _, arg := range args {
			if arg.URI.Match([]byte(uri)) {
				return jwt.NewRegexpScopeClaims(arg.Scopes...)
			}
		}
		return &DeniedClaims{fmt.Errorf("inaccessible uri: %v %v", method, uri)}
	}
}

type DeniedClaims struct {
	Err error
}

func (c DeniedClaims) Valid() error {
	return c.Err
}
