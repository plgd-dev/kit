package http

import (
	"context"
)

type Interceptor = func(ctx context.Context, method, uri string) (context.Context, error)
