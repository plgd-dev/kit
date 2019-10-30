package strings

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSet(t *testing.T) {
	a := []string{"1", "2", "3"}
	s := MakeSet(a...)
	require.Equal(t, a, s.ToSlice())
}

func TestAddingSet(t *testing.T) {
	a := []string{"1", "2", "3"}
	s := MakeSet()
	s.Add(a...)
	require.Equal(t, a, s.ToSlice())
}

func TestSetHasOneOf(t *testing.T) {
	s := MakeSet("1", "2", "3")
	require.True(t, s.HasOneOf("4", "3"))
}

func TestSetHasNoneOf(t *testing.T) {
	s := MakeSet("1", "2", "3")
	require.False(t, s.HasOneOf("4"))
}

func TestSetHasNone(t *testing.T) {
	s := MakeSet("1", "2", "3")
	require.True(t, s.HasOneOf())
}
