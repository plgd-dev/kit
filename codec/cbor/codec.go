package cbor

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ugorji/go/codec"
)

// Encode encodes v and returns bytes.
func Encode(v interface{}) ([]byte, error) {
	b := bytes.NewBuffer(make([]byte, 0, 128))
	err := WriteTo(b, v)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// WriteTo writes v to writer.
func WriteTo(w io.Writer, v interface{}) error {
	var h codec.CborHandle
	err := codec.NewEncoder(w, &h).Encode(v)
	if err != nil {
		return fmt.Errorf("CBOR encoder failed: %v", err)
	}
	return nil
}

// Decode decodes bytes and stores the result in v.
func Decode(b []byte, v interface{}) error {
	buf := bytes.NewBuffer(b)
	err := ReadFrom(buf, v)
	if err != nil {
		return err
	}
	return nil
}

// ReadFrom reads and stores the result in v.
func ReadFrom(w io.Reader, v interface{}) error {
	var h codec.CborHandle
	err := codec.NewDecoder(w, &h).Decode(v)
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
