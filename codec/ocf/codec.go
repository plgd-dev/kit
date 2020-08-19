package ocf

import (
	"fmt"
	"io/ioutil"

	"github.com/plgd-dev/go-coap/v2/message"
	"github.com/plgd-dev/kit/codec/cbor"
)

// VNDOCFCBORCodec encodes/decodes according to the CoAP content format/media type.
type VNDOCFCBORCodec struct{}

// ContentFormat used for encoding.
func (VNDOCFCBORCodec) ContentFormat() message.MediaType { return message.AppOcfCbor }

// Encode encodes v and returns bytes.
func (VNDOCFCBORCodec) Encode(v interface{}) ([]byte, error) {
	return cbor.Encode(v)
}

// Decode the CBOR payload of a COAP message.
func (VNDOCFCBORCodec) Decode(m *message.Message, v interface{}) error {
	if v == nil {
		return nil
	}
	mt, err := m.Options.ContentFormat()
	if err != nil {
		return fmt.Errorf("cannot get content format: %w", err)
	}
	if mt != message.AppCBOR && mt != message.AppOcfCbor {
		return fmt.Errorf("not a CBOR content format: %v", mt)
	}

	if err := cbor.ReadFrom(m.Body, v); err != nil {
		p, _ := m.Options.Path()
		return fmt.Errorf("decoding failed for the message %v on %v", m.Token, p)
	}
	return nil
}

// RawVNDOCFCBORCodec performes no encoding/decoding but
// it propagates/validates the CoAP content format/media type.
type RawVNDOCFCBORCodec struct{}

// ContentFormat used for encoding.
func (RawVNDOCFCBORCodec) ContentFormat() message.MediaType { return message.AppOcfCbor }

// Encode propagates the payload without any conversions.
func (c RawVNDOCFCBORCodec) Encode(v interface{}) ([]byte, error) {
	p, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected []byte")
	}
	return p, nil
}

// Decode validates the content format and
// propagates the payload to v as *[]byte without any conversions.
func (c RawVNDOCFCBORCodec) Decode(m *message.Message, v interface{}) error {
	if v == nil {
		return nil
	}
	mt, err := m.Options.ContentFormat()
	if err != nil {
		if m.Body == nil {
			return nil
		}
		return fmt.Errorf("cannot get content format: %w", err)
	}
	if mt != message.AppCBOR && mt != message.AppOcfCbor {
		return fmt.Errorf("not a CBOR content format: %v", mt)
	}

	p, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("expected *[]byte")
	}
	b, err := ioutil.ReadAll(m.Body)
	if err != nil {
		return fmt.Errorf("cannot read body: %w", err)
	}
	*p = b
	return nil
}

// NoCodec performes no encoding/decoding but
// it propagates/validates the CoAP content format/media type.
type NoCodec struct{ MediaType uint16 }

// ContentFormat propagates the CoAP media type.
func (c NoCodec) ContentFormat() message.MediaType { return message.MediaType(c.MediaType) }

// Encode propagates the payload without any conversions.
func (c NoCodec) Encode(v interface{}) ([]byte, error) {
	p, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected []byte")
	}
	return p, nil
}

// Decode validates the content format and
// propagates the payload to v as *[]byte without any conversions.
func (c NoCodec) Decode(m *message.Message, v interface{}) error {
	if v == nil {
		return nil
	}
	mt, err := m.Options.ContentFormat()
	if err != nil {
		if m.Body == nil {
			return nil
		}
		return fmt.Errorf("cannot get content format: %w", err)
	}
	if mt != c.ContentFormat() {
		return fmt.Errorf("unexpected content format: %v", mt)
	}

	p, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("expected *[]byte")
	}
	b, err := ioutil.ReadAll(m.Body)
	if err != nil {
		return fmt.Errorf("cannot read body: %w", err)
	}
	*p = b
	return nil
}

// DumpPayload dumps the COAP message payload to a string.
func DumpPayload(m *message.Message) (string, error) {
	mt, err := m.Options.ContentFormat()
	if err != nil {
		return "", fmt.Errorf("cannot get content format: %w", err)
	}
	switch mt {
	case message.TextPlain, message.AppJSON:
		b, err := ioutil.ReadAll(m.Body)
		if err != nil {
			return "", fmt.Errorf("cannot read body: %w", err)
		}
		return string(b), nil
	case message.AppCBOR, message.AppOcfCbor:
		b, err := ioutil.ReadAll(m.Body)
		if err != nil {
			return "", fmt.Errorf("cannot read body: %w", err)
		}
		return cbor.ToJSON(b)
	default:
		return "", fmt.Errorf("unknown content format %v", mt)
	}
}

// DumpHeader dumps the basic COAP message details to a string.
func DumpHeader(m *message.Message) string {
	buf := ""
	path, err := m.Options.Path()
	if err != nil {
		buf = fmt.Sprintf("%sPath: %v\n", buf, path)
	}
	cf, err := m.Options.ContentFormat()
	if err == nil {
		mt := message.MediaType(cf)
		buf = fmt.Sprintf("%sFormat: %v\n", buf, mt)
	}
	queries, err := m.Options.Queries()
	if err == nil {
		buf = fmt.Sprintf("%sQueries: %+v\n", buf, queries)
	}

	return buf
}

// Dump a COAP message to a string. If parsing fails, the error is appended.
func Dump(message *message.Message) string {
	header := DumpHeader(message)
	payload, err := DumpPayload(message)
	if err != nil {
		payload = err.Error()
	}
	return fmt.Sprintf("%s\nContent: %s\n", header, payload)
}
