package http

import (
	"errors"

	"github.com/gogo/protobuf/proto"
	"github.com/valyala/fasthttp"
)

// ProtoMarshaler defines methods for marshaling message to http
type ProtoMarshaler interface {
	proto.Message
	Size() int
	Marshal() ([]byte, error)
	MarshalTo(data []byte) (int, error)
}

// ProtoUnmarshaler defines methods for unmarshaling message to http
type ProtoUnmarshaler interface {
	proto.Message
	Unmarshal(data []byte) error
}

// WriteRequest sets the content type and encodes the body.
func WriteRequest(p ProtoMarshaler, r *fasthttp.Request) error { return write(p, &protoRequest{r}) }

// ReadRequest validates the content type and decodes the body.
func ReadRequest(p ProtoUnmarshaler, r *fasthttp.Request) error { return read(p, &protoRequest{r}) }

// WriteResponse sets the content type and encodes the body.
func WriteResponse(p ProtoMarshaler, r *fasthttp.Response) error { return write(p, &protoResponse{r}) }

// ReadResponse validates the content type and decodes the body.
func ReadResponse(p ProtoUnmarshaler, r *fasthttp.Response) error { return read(p, &protoResponse{r}) }

type content interface {
	Body() []byte
	SetBody(body []byte)
	contentType() []byte
	setContentType(contentType string)
}

type protoRequest struct {
	*fasthttp.Request
}

type protoResponse struct {
	*fasthttp.Response
}

func (r *protoRequest) contentType() []byte                { return r.Header.ContentType() }
func (r *protoRequest) setContentType(contentType string)  { r.Header.SetContentType(contentType) }
func (r *protoResponse) contentType() []byte               { return r.Header.ContentType() }
func (r *protoResponse) setContentType(contentType string) { r.Header.SetContentType(contentType) }

func read(p ProtoUnmarshaler, c content) error {
	if string(c.contentType()) != ProtobufContentType(p) {
		return errors.New("Invalid content type")
	}
	if err := p.Unmarshal(c.Body()); err != nil {
		return errors.New("Malformed body")
	}
	return nil
}

func write(p ProtoMarshaler, c content) error {
	var buf [1024]byte
	data := buf[:]
	size := p.Size()
	if size > len(data) {
		data = make([]byte, size)
	}
	n, err := p.MarshalTo(data)
	if err != nil {
		return err
	}
	data = data[:n]

	c.setContentType(ProtobufContentType(p))
	c.SetBody(data)
	return nil
}
