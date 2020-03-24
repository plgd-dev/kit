SERVICE_NAME = $(notdir $(CURDIR))
LATEST_TAG = vnext
VERSION_TAG = vnext-$(shell git rev-parse --short=7 --verify HEAD)

default: build

define build-docker-image
	docker build \
		--network=host \
		--tag ocfcloud/$(SERVICE_NAME):$(VERSION_TAG) \
		--tag ocfcloud/$(SERVICE_NAME):$(LATEST_TAG) \
		--target $(1) \
		.
endef

build-testcontainer:
	$(call build-docker-image,build)

build: build-testcontainer

test: clean build-testcontainer
#	sudo echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/50-unprivileged-ports.conf
#	sysctl --system
	docker run \
		--network=host \
		--mount type=bind,source="$(shell pwd)",target=/shared \
		ocfcloud/$(SERVICE_NAME):$(VERSION_TAG) \
		go test -v ./... -covermode=atomic -coverprofile=/shared/coverage.txt

proto/generate:
	protoc -I=. -I=${GOPATH}/src -I=${GOPATH}/src/github.com/gogo/protobuf/protobuf --go_out=${GOPATH}/src net/grpc/errorDetail.proto

clean:

.PHONY: build-testcontainer build-servicecontainer build test push clean proto/generate



