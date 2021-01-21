package client

import (
	"net/url"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

type Config struct {
	ClientID       string        `yaml:"clientID" json:"clientID"`
	ClientSecret   string        `yaml:"clientSecret" json:"clientSecret"`
	Scopes         []string      `yaml:"scopes" json:"scopes"`
	TokenURL       string        `yaml:"tokenURL" json:"tokenURL"`
	Audience       string        `yaml:"audience" json:"audience"`
	RequestTimeout time.Duration `yaml:"timeout" json:"timeout" default:"10s"`
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
		TokenURL:       c.TokenURL,
		EndpointParams: v,
	}
}
