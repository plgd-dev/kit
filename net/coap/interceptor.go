package coap

import (
	"context"

	"github.com/go-ocf/go-coap/v2/message/codes"
)

type Interceptor = func(ctx context.Context, code codes.Code, path string) (context.Context, error)
