package cbor

import (
	"bytes"
	"fmt"

	"github.com/ugorji/go/codec"
)

// Encode encodes v and returns bytes.
func Encode(v interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	err := codec.NewEncoder(b, new(codec.CborHandle)).Encode(v)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoder failed: %v", err)
	}
	return b.Bytes(), nil
}

// Decode decodes bytes and stores the result in v.
func Decode(b []byte, v interface{}) error {
	err := codec.NewDecoderBytes(b, new(codec.CborHandle)).Decode(v)
	if err != nil {
		return fmt.Errorf("CBOR decoder failed: %v", err)
	}
	return nil
}

// ToJSON converts CBOR to JSON.
func ToJSON(cbor []byte) (string, error) {
	var m interface{}
	if err := Decode(cbor, &m); err != nil {
		return "", err
	}
	b := new(bytes.Buffer)
	h := new(codec.JsonHandle)
	h.BasicHandle.Canonical = true
	enc := codec.NewEncoder(b, h)
	if err := enc.Encode(m); err != nil {
		return "", err
	}
	return b.String(), nil
}
