package http

import "github.com/gogo/protobuf/proto"

// ProtobufContentType content type strings for Protobuf.
func ProtobufContentType(s proto.Message) string {
	return "application/protobuf; proto=" + proto.MessageName(s)
}
