package manager

import (
	"net/url"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

type Endpoint struct {
	TokenURL string `envconfig:"TOKEN_URL" env:"TOKEN_URL" long:"token_url"`
}

type Config struct {
	ClientID       string        `envconfig:"CLIENT_ID" env:"CLIENT_ID" long:"client_id"`
	ClientSecret   string        `envconfig:"CLIENT_SECRET" env:"CLIENT_SECRET" long:"client_secret"`
	Scopes         []string      `envconfig:"SCOPES" env:"SCOPES" long:"scopes"`
	Endpoint       Endpoint      `envconfig:"ENDPOINT" env:"ENDPOINT" long:"endpoint"`
	Audience       string        `envconfig:"AUDIENCE" env:"AUDIENCE" long:"audience"`
	RequestTimeout time.Duration `envconfig:"REQUEST_TIMEOUT" env:"REQUEST_TIMEOUT" long:"request_timeout" default:"10s"`
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
