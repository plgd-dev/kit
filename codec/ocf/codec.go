package ocf

import (
	"fmt"

	coap "github.com/go-ocf/go-coap"
	"github.com/go-ocf/kit/codec/cbor"
)

// VNDOCFCBORCodec encodes/decodes according to the CoAP content format/media type.
type VNDOCFCBORCodec struct{}

// ContentFormat used for encoding.
func (VNDOCFCBORCodec) ContentFormat() coap.MediaType { return coap.AppOcfCbor }

// Encode encodes v and returns bytes.
func (VNDOCFCBORCodec) Encode(v interface{}) ([]byte, error) {
	return cbor.Encode(v)
}

// Decode the CBOR payload of a COAP message.
func (VNDOCFCBORCodec) Decode(m coap.Message, v interface{}) error {
	if v == nil {
		return nil
	}
	cf := m.Option(coap.ContentFormat)
	mt, ok := cf.(coap.MediaType)

	if !ok || (mt != coap.AppCBOR && mt != coap.AppOcfCbor) {
		return fmt.Errorf("not a CBOR content format: %v", cf)
	}

	if err := cbor.Decode(m.Payload(), v); err != nil {
		return fmt.Errorf("decoding failed for the message %v on %v", m.MessageID(), m.PathString())
	}
	return nil
}

// NoCodec performes no encoding/decoding but
// it propagates/validates the CoAP content format/media type.
type NoCodec struct{ MediaType uint16 }

// ContentFormat propagates the CoAP media type.
func (c NoCodec) ContentFormat() coap.MediaType { return coap.MediaType(c.MediaType) }

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
func (c NoCodec) Decode(m coap.Message, v interface{}) error {
	if v == nil {
		return nil
	}
	cf := m.Option(coap.ContentFormat)
	mt, ok := cf.(coap.MediaType)
	if !ok {
		if len(m.Payload()) == 0 {
			return nil
		}
		if mt != c.ContentFormat() {
			return fmt.Errorf("unexpected content format: %v", cf)
		}
	}

	p, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("expected *[]byte")
	}
	*p = m.Payload()
	return nil
}

// DumpPayload dumps the COAP message payload to a string.
func DumpPayload(message coap.Message) (string, error) {
	cf := message.Option(coap.ContentFormat)
	mt, ok := cf.(coap.MediaType)
	if !ok {
		return "", fmt.Errorf("unknown content format %v", cf)
	}
	switch mt {
	case coap.TextPlain, coap.AppJSON:
		return string(message.Payload()), nil
	case coap.AppCBOR, coap.AppOcfCbor:
		return cbor.ToJSON(message.Payload())
	default:
		return "", fmt.Errorf("unknown content format %v", cf)
	}
}

// DumpHeader dumps the basic COAP message details to a string.
func DumpHeader(message coap.Message) string {
	return fmt.Sprintf("Path: %v\nCode: %v\nType: %v\nFormat: %v\nQuery: %+v\n",
		message.PathString(),
		message.Code(),
		message.Type(),
		message.Option(coap.ContentFormat),
		message.Options(coap.URIQuery))
}

// Dump a COAP message to a string. If parsing fails, the error is appended.
func Dump(message coap.Message) string {
	header := DumpHeader(message)
	payload, err := DumpPayload(message)
	if err != nil {
		payload = err.Error()
	}
	return fmt.Sprintf("%s\nContent: %s\n", header, payload)
}
