package coap

import (
	"fmt"

	gocoap "github.com/go-ocf/go-coap"
	"github.com/go-ocf/kit/codec/cbor"
	"github.com/go-ocf/kit/codec/json"
)

type EncodeFunc = func(v interface{}) ([]byte, error)

// GetAccept returns expected content format by client
func GetAccept(req gocoap.Message) gocoap.MediaType {
	ct, ok := req.Option(gocoap.Accept).(gocoap.MediaType)
	if !ok {
		return gocoap.AppOcfCbor
	}
	return ct
}

// GetEncoder returns encoder by accept
func GetEncoder(accept gocoap.MediaType) (EncodeFunc, error) {
	switch accept {
	case gocoap.AppJSON:
		return json.Encode, nil
	case gocoap.AppCBOR, gocoap.AppOcfCbor:
		return cbor.Encode, nil
	default:
		return nil, fmt.Errorf("unsupported type (%v)", accept)
	}
}
