package jwt

import (
	"fmt"
	"sync"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

type KeyCache struct {
	url  string
	m    sync.Mutex
	keys *jwk.Set
}

func NewKeyCache(url string) *KeyCache {
	return &KeyCache{url: url}
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
	return key.Materialize()
}

func (c *KeyCache) LookupKey(token *jwt.Token) (jwk.Key, error) {
	id, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in JWT")
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
	keys, err := jwk.FetchHTTP(c.url)
	if err != nil {
		return fmt.Errorf("could not fetch JWK: %v", err)
	}

	c.m.Lock()
	defer c.m.Unlock()

	c.keys = keys
	return nil
}
