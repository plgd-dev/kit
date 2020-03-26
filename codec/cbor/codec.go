package cbor

import (
	"bytes"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/ugorji/go/codec"
)

// Encode encodes v and returns bytes.
func Encode(v interface{}) ([]byte, error) {
	return cbor.Marshal(v)
}

// WriteTo writes v to writer.
func WriteTo(w io.Writer, v interface{}) error {
	return cbor.NewEncoder(w).Encode(v)
}

// Decode decodes bytes and stores the result in v.
func Decode(b []byte, v interface{}) error {
	return cbor.Unmarshal(b, v)
}

// ReadFrom reads and stores the result in v.
func ReadFrom(w io.Reader, v interface{}) error {
	return cbor.NewDecoder(w).Decode(v)
}

// ToJSON converts CBOR to JSON.
func ToJSON(cbor []byte) (string, error) {
	var m interface{}
	if err := Decode(cbor, &m); err != nil {
		return "", err
	}
	b := bytes.NewBuffer(make([]byte, 0, 1024))
	h := codec.JsonHandle{}
	h.BasicHandle.Canonical = true
	enc := codec.NewEncoder(b, &h)
	if err := enc.Encode(m); err != nil {
		return "", err
	}
	return b.String(), nil
}
