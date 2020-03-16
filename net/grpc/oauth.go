package grpc

import (
	"golang.org/x/oauth2"
	"google.golang.org/grpc/credentials"
	"context"
)


type OAuthGetTokenFunc = func(ctx context.Context) (*oauth2.Token, error)

// oauthAccess supplies PerRPCCredentials from a given token.
type oauthAccess struct {
	getTokenFunc OAuthGetTokenFunc
}

// NewOAuthAccess constructs the PerRPCCredentials using a given token.
func NewOAuthAccess(getTokenFunc OAuthGetTokenFunc) credentials.PerRPCCredentials {
	return oauthAccess{getTokenFunc: getTokenFunc}
}

func (oa oauthAccess) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token, err := oa.getTokenFunc(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"authorization": token.Type() + " " + token.AccessToken,
	}, nil
}

func (oa oauthAccess) RequireTransportSecurity() bool {
	return true
}