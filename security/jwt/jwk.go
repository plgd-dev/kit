package jwt

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"

	transport "github.com/plgd-dev/kit/net/http/transport"
)

type KeyCache struct {
	url  string
	http *http.Client
	m    sync.Mutex
	keys *jwk.Set
}

func NewKeyCache(url string, tls *tls.Config) *KeyCache {
	transport := transport.NewDefaultTransport()
	transport.TLSClientConfig = tls
	client := http.Client{Transport: transport}
	return &KeyCache{url: url, http: &client}
}

func (c *KeyCache) GetOrFetchKey(token *jwt.Token) (interface{}, error) {
	if k, err := c.GetKey(token); err == nil {
		return k, nil
	}
	if err := c.FetchKeys(); err != nil {
		return nil, err
	}
	return c.GetKey(token)
}

func (c *KeyCache) GetKey(token *jwt.Token) (interface{}, error) {
	key, err := c.LookupKey(token)
	if err != nil {
		return nil, err
	}
	var v interface{}
	return v, key.Raw(&v)
}

func (c *KeyCache) LookupKey(token *jwt.Token) (jwk.Key, error) {
	id, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing key id in token")
	}

	c.m.Lock()
	defer c.m.Unlock()

	if c.keys == nil {
		return nil, fmt.Errorf("empty JWK cache")
	}
	for _, key := range c.keys.LookupKeyID(id) {
		if key.Algorithm() == token.Method.Alg() {
			return key, nil
		}
	}
	return nil, fmt.Errorf("could not find JWK")
}

func (c *KeyCache) FetchKeys() error {
	keys, err := jwk.FetchHTTP(c.url, jwk.WithHTTPClient(c.http))
	if err != nil {
		return fmt.Errorf("could not fetch JWK: %w", err)
	}

	c.m.Lock()
	defer c.m.Unlock()

	c.keys = keys
	return nil
}
