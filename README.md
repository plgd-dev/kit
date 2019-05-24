[![Build Status](https://travis-ci.com/go-ocf/kit.svg?branch=master)](https://travis-ci.com/go-ocf/kit)
[![codecov](https://codecov.io/gh/go-ocf/kit/branch/master/graph/badge.svg)](https://codecov.io/gh/go-ocf/kit)
[![Go Report](https://goreportcard.com/badge/github.com/go-ocf/kit)](https://goreportcard.com/report/github.com/go-ocf/kit)

# kit


## Build

Some components in `net` depend on the `security.IsInsecure` flag, which needs to be generated as follows:

Secure
```sh
go generate ./security
```

Insecure
```sh
OCF_INSECURE=TRUE go generate ./security
```
