package sync

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRefCounter_Increment(t *testing.T) {
	type fields struct {
		count           int64
		data            interface{}
		releaseDataFunc ReleaseDataFunc
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "valid",
			fields: fields{
				count: 1,
				data:  1,
			},
		},
		{
			name: "invalid data",
			fields: fields{
				count: 1,
				data:  nil,
			},
			wantErr: true,
		},
		{
			name: "invalid count",
			fields: fields{
				count: 0,
				data:  nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RefCounter{
				count:           tt.fields.count,
				data:            tt.fields.data,
				releaseDataFunc: tt.fields.releaseDataFunc,
			}
			err := r.Increment()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRefCounter_Decrement(t *testing.T) {
	type fields struct {
		count int64
		data  interface{}
	}
	tests := []struct {
		name                string
		fields              fields
		wantErr             bool
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
			wantErr: true,
		},
		{
			name: "invalid - data",
			fields: fields{
				count: 0,
				data:  nil,
			},
			wantErr: true,
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
			err := r.Decrement(ctx)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.releaseDataFuncUsed, *releaseDataFuncUsed)
			}
		})
	}
}
