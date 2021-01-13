package manager

import (
	"net/url"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

type Endpoint struct {
	TokenURL string `long:"token-url" json:"token-url"`
}

type Config struct {
	ClientID       string        `long:"client-id" json:"client-id"`
	ClientSecret   string        `long:"client-secret" json:"client-secret"`
	Scopes         []string      `long:"scopes" json:"scopes"`
	Endpoint       Endpoint      `long:"endpoint" json:"endpoint"`
	Audience       string        `long:"audience" json:"audience"`
	RequestTimeout time.Duration `long:"request-timeout" json:"request-timeout" default:"10s"`
}

// ToClientCrendtials converts to clientcredentials.Config
func (c Config) ToClientCrendtials() clientcredentials.Config {
	v := make(url.Values)
	if c.Audience != "" {
		v.Set("audience", c.Audience)
	}

	return clientcredentials.Config{
		ClientID:       c.ClientID,
		ClientSecret:   c.ClientSecret,
		Scopes:         c.Scopes,
		TokenURL:       c.Endpoint.TokenURL,
		EndpointParams: v,
	}
}
