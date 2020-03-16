package manager

import (
	"net/url"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

type Endpoint struct {
	TokenURL string `envconfig:"TOKEN_URL" env:"TOKEN_URL"`
}

type Config struct {
	ClientID       string        `envconfig:"CLIENT_ID" env:"CLIENT_ID"`
	ClientSecret   string        `envconfig:"CLIENT_SECRET" env:"CLIENT_SECRET"`
	Scopes         []string      `envconfig:"SCOPES" env:"SCOPES"`
	Endpoint       Endpoint      `envconfig:"ENDPOINT" env:"ENDPOINT"`
	Audience       string        `envconfig:"AUDIENCE" env:"AUDIENCE"`
	ResponseMode   string        `envconfig:"RESPONSE_MODE" env:"RESPONSE_MODE"`
	RequestTimeout time.Duration `envconfig:"REQUEST_TIMEOUT" default:"10s"`
}

// ToClientCrendtials converts to clientcredentials.Config
func (c Config) ToClientCrendtials() clientcredentials.Config {
	v := make(url.Values)
	if c.Audience != "" {
		v.Set("audience", c.Audience)
	}
	if c.ResponseMode != "" {
		v.Set("response_mode", c.ResponseMode)
	}

	return clientcredentials.Config{
		ClientID:       c.ClientID,
		ClientSecret:   c.ClientSecret,
		Scopes:         c.Scopes,
		TokenURL:       c.Endpoint.TokenURL,
		EndpointParams: v,
	}
}
