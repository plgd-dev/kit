package transport

import (
	"net/http"
)

// NewDefaultTransport creates a copy of http.DefaultTransport.
func NewDefaultTransport() *http.Transport {
	defaultTransport := http.DefaultTransport.(*http.Transport)
	return &http.Transport{
		TLSClientConfig:        defaultTransport.TLSClientConfig,
		Proxy:                  defaultTransport.Proxy,
		DialContext:            defaultTransport.DialContext,
		Dial:                   defaultTransport.Dial,
		DialTLS:                defaultTransport.DialTLS,
		TLSHandshakeTimeout:    defaultTransport.TLSHandshakeTimeout,
		DisableKeepAlives:      defaultTransport.DisableKeepAlives,
		DisableCompression:     defaultTransport.DisableCompression,
		MaxIdleConns:           defaultTransport.MaxIdleConns,
		MaxIdleConnsPerHost:    defaultTransport.MaxIdleConnsPerHost,
		MaxConnsPerHost:        defaultTransport.MaxConnsPerHost,
		IdleConnTimeout:        defaultTransport.IdleConnTimeout,
		ResponseHeaderTimeout:  defaultTransport.ResponseHeaderTimeout,
		ExpectContinueTimeout:  defaultTransport.ExpectContinueTimeout,
		TLSNextProto:           defaultTransport.TLSNextProto,
		ProxyConnectHeader:     defaultTransport.ProxyConnectHeader,
		MaxResponseHeaderBytes: defaultTransport.MaxResponseHeaderBytes,
	}
}
