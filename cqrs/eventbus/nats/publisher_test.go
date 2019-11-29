package nats

import (
	"testing"

	nats "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

func TestNewPublisher(t *testing.T) {
	bus, err := NewPublisher(Config{
		URL: nats.DefaultURL,
	})
	assert.NoError(t, err)
	assert.NotNil(t, bus)
	defer bus.Close()
}
