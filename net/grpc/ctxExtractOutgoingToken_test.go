package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCtxExtractOutgoingToken(t *testing.T) {
	token := "token"
	got, err := CtxExtractOutgoingToken(CtxWithToken(context.Background(), token))
	require.NoError(t, err)
	require.Equal(t, token, got)
}
