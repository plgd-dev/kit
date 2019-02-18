package cqrs

import (
	"testing"

	"github.com/go-ocf/kit/cqrs/protobuf"
	"github.com/stretchr/testify/assert"
)

func TestProtobufMarshaler(t *testing.T) {
	req := protobuf.AuthorizationContext{}

	out, err := Marshal(&req)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)

	a := struct {
	}{}
	_, err = Marshal(a)
	assert.Error(t, err)

	resp := protobuf.AuthorizationContext{}
	err = Unmarshal(out, &resp)
	assert.NoError(t, err)

	err = Unmarshal(out, a)
	assert.Error(t, err)
}

func TestDummyForCoverage(t *testing.T) {
	device := "dev"
	version := uint64(1234)
	corId := "a"
	userId := "u"

	TimeNowMs()
	em := MakeEventMeta(version)
	assert.Equal(t, version, em.Version)
	ac := MakeAuditContext(&protobuf.AuthorizationContext{UserId: userId, DeviceId: device}, corId)
	assert.Equal(t, corId, ac.CorrelationId)
	assert.Equal(t, userId, ac.UserId)
	assert.Equal(t, device, ac.DeviceId)
}
