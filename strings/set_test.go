package strings

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSet(t *testing.T) {
	a := []string{"1", "2", "3"}
	s := MakeSet(a...)
	slice := s.ToSlice()
	sort.Strings(slice)
	require.Equal(t, a, slice)
}

func TestAddingSet(t *testing.T) {
	a := []string{"1", "2", "3"}
	s := MakeSet()
	s.Add(a...)
	slice := s.ToSlice()
	sort.Strings(slice)
	require.Equal(t, a, slice)
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
