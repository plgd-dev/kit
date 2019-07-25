package jwt

import (
	"fmt"

	"github.com/go-ocf/kit/strings"
)

type ScopeClaims struct {
	Claims
	requiredScope string
}

func NewScopeClaims(scope string) ScopeClaims {
	if scope == "" {
		panic("missing scope")
	}
	return ScopeClaims{requiredScope: scope}
}

func (c ScopeClaims) Valid() error {
	if err := c.Claims.Valid(); err != nil {
		return err
	}
	if !strings.SliceContains(c.Scope, c.requiredScope) {
		return fmt.Errorf("missing scope: %s", c.requiredScope)
	}
	return nil
}
