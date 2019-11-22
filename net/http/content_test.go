package http

import "fmt"

func ExampleProtobufContentType() {
	var t TestRequest
	fmt.Println(ProtobufContentType(&t))
	// Output: application/protobuf; proto=http.test.TestRequest
}
