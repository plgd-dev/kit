package net

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseString(t *testing.T) {
	ip6 := "[fe80::6262:3c03:5549:6ad6%eno1]:34786"
	schema := "coap"
	v, err := ParseString(schema, ip6)
	require.NoError(t, err)
	assert.Equal(t, schema+"://"+ip6, v.URL())
}
