package strings

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNilToSlice(t *testing.T) {
	require.Nil(t, ToSlice(nil))
}

func TestEmptyStringToSlice(t *testing.T) {
	require.Nil(t, ToSlice(""))
}

func TestEmptySliceToSlice(t *testing.T) {
	require.Equal(t, []string{}, ToSlice([]string{}))
}

func TestStringToSlice(t *testing.T) {
	require.Equal(t, []string{"test"}, ToSlice("test"))
}

func TestStringsToSlice(t *testing.T) {
	require.Equal(t, []string{"one", "two"}, ToSlice([]string{"one", "two"}))
}

func TestInterfacesToSlice(t *testing.T) {
	require.Equal(t, []string{"one", "two"}, ToSlice([]interface{}{"one", "two"}))
}

func TestIntToSlice(t *testing.T) {
	require.Nil(t, ToSlice(42))
}

func TestMixedToSlice(t *testing.T) {
	require.Nil(t, ToSlice([]interface{}{"test", 42}))
}
