package coap

import (
	"context"
	gocoap "github.com/go-ocf/go-coap"
)

type Interceptor = func(ctx context.Context, code gocoap.COAPCode, path string) (context.Context, error)
