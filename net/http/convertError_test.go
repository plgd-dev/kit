package http

import (
	"fmt"
	"net/http"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/stretchr/testify/assert"
	coapStatus "github.com/go-ocf/kit/net/coap/status"
	coapCodes "github.com/go-ocf/go-coap/codes"
	gocoap "github.com/go-ocf/go-coap"
	"testing"
)

func TestErrToStatus(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{name:"ol", args: args{err: nil}, want: http.StatusOK},
		{name:"grpc", args: args{err: status.Error(codes.PermissionDenied, "grpc error")}, want: http.StatusForbidden},
		{
			name:"coap",
			args: args{
				err: coapStatus.Error(gocoap.NewTcpMessage(gocoap.MessageParams{Code: coapCodes.Forbidden}), fmt.Errorf("coap error")),
			},
			want: http.StatusForbidden,
		},
		{name:"grpc", args: args{err: fmt.Errorf("unknown error")}, want: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ErrToStatus(tt.args.err);
			assert.Equal(t, tt.want, got)
		})
	}
}
