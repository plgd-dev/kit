package kafka

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPublisher(t *testing.T) {
	bus, err := NewPublisher(Config{
		Endpoints: []string{"localhost:9092"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, bus)
	defer bus.Close()
}
