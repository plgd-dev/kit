FROM golang:1.13.0-alpine3.10 AS build
RUN apk add --no-cache curl git build-base && \
	curl -SL -o /usr/bin/dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64 && \
	chmod +x /usr/bin/dep
WORKDIR $GOPATH/src/github.com/go-ocf/kit
COPY . .

RUN dep ensure -v --vendor-only
