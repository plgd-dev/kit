package json

import (
	"bytes"
	"fmt"

	"github.com/go-ocf/kit/codec/cbor"

	"github.com/ugorji/go/codec"
)

// Encode encodes v and returns bytes.
func Encode(v interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	var h codec.JsonHandle
	h.BasicHandle.Canonical = true
	err := codec.NewEncoder(b, &h).Encode(v)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoder failed: %v", err)
	}
	return b.Bytes(), nil
}

// Decode decodes bytes and stores the result in v.
func Decode(b []byte, v interface{}) error {
	err := codec.NewDecoderBytes(b, new(codec.JsonHandle)).Decode(v)
	if err != nil {
		return fmt.Errorf("CBOR decoder failed: %v", err)
	}
	return nil
}

// ToCBOR converts JSON to CBOR.
func ToCBOR(json string) ([]byte, error) {
	var m interface{}
	if err := Decode([]byte(json), &m); err != nil {
		return nil, err
	}
	return cbor.Encode(m)
}
