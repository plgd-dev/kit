package sync

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRefCounter_Acquire(t *testing.T) {
	type fields struct {
		count           int64
		data            interface{}
		releaseDataFunc ReleaseDataFunc
	}
	tests := []struct {
		name      string
		fields    fields
		wantPanic bool
	}{
		{
			name: "valid",
			fields: fields{
				count: 1,
				data:  1,
			},
		},
		{
			name: "invalid count",
			fields: fields{
				count: 0,
				data:  nil,
			},
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RefCounter{
				count:           tt.fields.count,
				data:            tt.fields.data,
				releaseDataFunc: tt.fields.releaseDataFunc,
			}
			if tt.wantPanic {
				require.Panics(t, r.Acquire)
			} else {
				require.NotPanics(t, r.Acquire)
			}
		})
	}
}

func TestRefCounter_Release(t *testing.T) {
	type fields struct {
		count int64
		data  interface{}
	}
	tests := []struct {
		name                string
		fields              fields
		wantPanic           bool
		releaseDataFuncUsed bool
	}{
		{
			name: "valid - release",
			fields: fields{
				count: 1,
				data:  1,
			},
			releaseDataFuncUsed: true,
		},
		{
			name: "valid",
			fields: fields{
				count: 2,
				data:  1,
			},
			releaseDataFuncUsed: false,
		},
		{
			name: "invalid - count",
			fields: fields{
				count: 0,
				data:  1,
			},
			wantPanic: true,
		},
		{
			name: "invalid - data",
			fields: fields{
				count: 0,
				data:  nil,
			},
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			releaseDataFuncUsed := new(bool)
			r := &RefCounter{
				count: tt.fields.count,
				data:  tt.fields.data,
				releaseDataFunc: func(ctx context.Context, data interface{}) error {
					*releaseDataFuncUsed = true
					return nil
				},
			}
			ctx := context.Background()

			if tt.wantPanic {
				require.Panics(t, func() {
					r.Release(ctx)
				})
			} else {
				require.NotPanics(t, func() {
					r.Release(ctx)
				})
				require.Equal(t, tt.releaseDataFuncUsed, *releaseDataFuncUsed)
			}
		})
	}
}
