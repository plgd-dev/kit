package manager

import (
	"net/url"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

type Endpoint struct {
	TokenURL string `envconfig:"TOKEN_URL" env:"TOKEN_URL" json:"token_url"`
}

type Config struct {
	ClientID       string        `envconfig:"CLIENT_ID" env:"CLIENT_ID" json:"client-id"`
	ClientSecret   string        `envconfig:"CLIENT_SECRET" env:"CLIENT_SECRET" json:"client-secret"`
	Scopes         []string      `envconfig:"SCOPES" env:"SCOPES" json:"scopes"`
	Endpoint       Endpoint      `envconfig:"ENDPOINT" env:"ENDPOINT" json:"endpoint"`
	Audience       string        `envconfig:"AUDIENCE" env:"AUDIENCE" json:"audience"`
	RequestTimeout time.Duration `envconfig:"REQUEST_TIMEOUT" env:"REQUEST_TIMEOUT" json:"request-timeout" default:"10s"`
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
