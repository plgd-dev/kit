package coap

import (
	"fmt"

	"github.com/go-ocf/go-coap/v2/message"
	"github.com/go-ocf/kit/codec/cbor"
	"github.com/go-ocf/kit/codec/json"
)

type EncodeFunc = func(v interface{}) ([]byte, error)

// GetAccept returns expected content format by client
func GetAccept(req *message.Message) message.MediaType {
	ct, err := req.Options.GetUint32(message.Accept)
	if err != nil {
		return message.AppOcfCbor
	}
	return message.MediaType(ct)
}

// GetEncoder returns encoder by accept
func GetEncoder(accept message.MediaType) (EncodeFunc, error) {
	switch accept {
	case message.AppJSON:
		return json.Encode, nil
	case message.AppCBOR, message.AppOcfCbor:
		return cbor.Encode, nil
	default:
		return nil, fmt.Errorf("unsupported type (%v)", accept)
	}
}
