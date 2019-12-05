package grpconv

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
)

func TestToHTTPCode(t *testing.T) {
	type args struct {
		code codes.Code
		def  int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{name: "codes.OK", args: args{code: codes.OK, def: 9999}, want: http.StatusOK},
		{name: "codes.Canceled", args: args{code: codes.Canceled, def: 9999}, want: http.StatusRequestTimeout},
		{name: "codes.Unknown", args: args{code: codes.Unknown, def: 9999}, want: http.StatusInternalServerError},
		{name: "codes.InvalidArgument", args: args{code: codes.InvalidArgument, def: 9999}, want: http.StatusBadRequest},
		{name: "codes.DeadlineExceeded", args: args{code: codes.DeadlineExceeded, def: 9999}, want: http.StatusGatewayTimeout},
		{name: "codes.NotFound", args: args{code: codes.NotFound, def: 9999}, want: http.StatusNotFound},
		{name: "codes.AlreadyExists", args: args{code: codes.AlreadyExists, def: 9999}, want: http.StatusConflict},
		{name: "codes.PermissionDenied", args: args{code: codes.PermissionDenied, def: 9999}, want: http.StatusForbidden},
		{name: "codes.Unauthenticated", args: args{code: codes.Unauthenticated, def: 9999}, want: http.StatusUnauthorized},
		{name: "codes.ResourceExhausted", args: args{code: codes.ResourceExhausted, def: 9999}, want: http.StatusTooManyRequests},
		{name: "codes.FailedPrecondition", args: args{code: codes.FailedPrecondition, def: 9999}, want: http.StatusBadRequest},
		{name: "codes.Aborted", args: args{code: codes.Aborted, def: 9999}, want: http.StatusConflict},
		{name: "codes.OutOfRange", args: args{code: codes.OutOfRange, def: 9999}, want: http.StatusBadRequest},
		{name: "codes.Unimplemented", args: args{code: codes.Unimplemented, def: 9999}, want: http.StatusNotImplemented},
		{name: "codes.Internal", args: args{code: codes.Internal, def: 9999}, want: http.StatusInternalServerError},
		{name: "codes.Unavailable", args: args{code: codes.Unavailable, def: 9999}, want: http.StatusServiceUnavailable},
		{name: "codes.DataLoss", args: args{code: codes.DataLoss, def: 9999}, want: http.StatusInternalServerError},
		{name: "invalid", args: args{code: codes.Code(99999), def: 9999}, want: 9999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToHTTPCode(tt.args.code, tt.args.def)
			assert.Equal(t, tt.want, got)
		})
	}
}
