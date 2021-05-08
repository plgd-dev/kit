module github.com/plgd-dev/kit

go 1.13

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dsnet/golib/memfile v1.0.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9
	github.com/fxamacker/cbor/v2 v2.2.0
	github.com/go-acme/lego v2.7.2+incompatible
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.1
	github.com/gorilla/mux v1.7.4
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lestrrat-go/jwx v1.0.2
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pion/dtls/v2 v2.0.9
	github.com/plgd-dev/go-coap/v2 v2.4.0
	github.com/stretchr/testify v1.7.0
	github.com/ugorji/go/codec v1.1.7
	github.com/valyala/fasthttp v1.12.0
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/zap v1.15.0
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf
	golang.org/x/net v0.0.0-20210508051633-16afe75a6701
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20210507161434-a76c4d0a0096 // indirect
	google.golang.org/genproto v0.0.0-20200511104702-f5ebc3bea380
	google.golang.org/grpc v1.29.1
	gopkg.in/yaml.v2 v2.2.8
)

replace gopkg.in/yaml.v2 v2.2.8 => github.com/cizmazia/yaml v0.0.0-20200220134304-2008791f5454
