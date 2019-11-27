package jwt

import (
	"fmt"
	"regexp"
)

type ScopeClaims struct {
	Claims
	requiredScopes []*regexp.Regexp
}

func NewScopeClaims(scope ...string) *ScopeClaims {
	requiredScopes := make([]*regexp.Regexp, 0, len(scope))
	for _, s := range scope {
		requiredScopes = append(requiredScopes, regexp.MustCompile(regexp.QuoteMeta(s)))
	}
	return NewRegexpScopeClaims(requiredScopes...)
}

func NewRegexpScopeClaims(scope ...*regexp.Regexp) *ScopeClaims {
	if len(scope) == 0 {
		panic("missing scope")
	}
	return &ScopeClaims{requiredScopes: scope}
}

func (c *ScopeClaims) Valid() error {
	if err := c.Claims.Valid(); err != nil {
		return err
	}
	for _, scope := range c.GetScope() {
		for _, requiredScope := range c.requiredScopes {
			if (requiredScope.MatchString(scope)) {
				return nil
			}
		}
	}
	requiredScopes := make([]string, 0, len(c.requiredScopes))
	for _, scope := range c.requiredScopes {
		requiredScopes = append(requiredScopes, scope.String())
	}
	return fmt.Errorf("must contains one of scopes: %+v", requiredScopes)
}
