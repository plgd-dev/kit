package coap

import (
	"context"

	"github.com/go-ocf/go-coap/codes"
)

type Interceptor = func(ctx context.Context, code codes.Code, path string) (context.Context, error)
