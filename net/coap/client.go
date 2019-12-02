package coap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	uuid "github.com/gofrs/uuid"
	dtls "github.com/pion/dtls/v2"
	"github.com/pion/logging"

	gocoap "github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	codecOcf "github.com/go-ocf/kit/codec/ocf"
	"github.com/go-ocf/kit/net/coap/status"
	"github.com/go-ocf/kit/security"
)

type Client struct {
	conn *gocoap.ClientConn
}

// Codec encodes/decodes according to the CoAP content format/media type.
type Codec interface {
	ContentFormat() gocoap.MediaType
	Encode(v interface{}) ([]byte, error)
	Decode(m gocoap.Message, v interface{}) error
}

var ExtendedKeyUsage_IDENTITY_CERTIFICATE = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44924, 1, 6}

func GetDeviceIDFromIndetityCertificate(cert *x509.Certificate) (string, error) {
	// verify EKU manually
	ekuHasClient := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			ekuHasClient = true
			break
		}
	}
	if !ekuHasClient {
		return "", fmt.Errorf("not contains ExtKeyUsageClientAuth")
	}
	ekuHasOcfId := false
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.Equal(ExtendedKeyUsage_IDENTITY_CERTIFICATE) {
			ekuHasOcfId = true
			break
		}
	}
	if !ekuHasOcfId {
		return "", fmt.Errorf("not contains ExtKeyUsage with OCF ID(1.3.6.1.4.1.44924.1.6")
	}
	cn := strings.Split(cert.Subject.CommonName, ":")
	if len(cn) != 2 {
		return "", fmt.Errorf("invalid subject common name: %v", cert.Subject.CommonName)
	}
	if strings.ToLower(cn[0]) != "uuid" {
		return "", fmt.Errorf("invalid subject common name %v: 'uuid' - not found", cert.Subject.CommonName)
	}
	deviceId, err := uuid.FromString(cn[1])
	if err != nil {
		return "", fmt.Errorf("invalid subject common name %v: %v", cert.Subject.CommonName, err)
	}
	return deviceId.String(), nil
}

func VerifyIndetityCertificate(cert *x509.Certificate) error {
	// verify EKU manually
	ekuHasClient := false
	ekuHasServer := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			ekuHasClient = true
		}
		if eku == x509.ExtKeyUsageServerAuth {
			ekuHasServer = true
		}
	}
	if !ekuHasClient {
		return fmt.Errorf("not contains ExtKeyUsageClientAuth")
	}
	if !ekuHasServer {
		return fmt.Errorf("not contains ExtKeyUsageServerAuth")
	}
	_, err := GetDeviceIDFromIndetityCertificate(cert)
	if err != nil {
		return err
	}

	return nil
}

func NewClient(conn *gocoap.ClientConn) *Client {
	return &Client{conn: conn}
}

type OptionFunc = func(gocoap.Message)

func WithInterface(in string) OptionFunc {
	return func(req gocoap.Message) {
		req.AddOption(gocoap.URIQuery, "if="+in)
	}
}

func WithResourceType(in string) OptionFunc {
	return func(req gocoap.Message) {
		req.AddOption(gocoap.URIQuery, "rt="+in)
	}
}

func WithInstanceID(in int) OptionFunc {
	return func(req gocoap.Message) {
		req.AddOption(gocoap.URIQuery, "ins="+strconv.Itoa(in))
	}
}

func WithDeviceID(in string) OptionFunc {
	return func(req gocoap.Message) {
		req.AddOption(gocoap.URIQuery, "di="+in)
	}
}

func WithCredentialId(in int) OptionFunc {
	return func(req gocoap.Message) {
		req.AddOption(gocoap.URIQuery, "credid="+strconv.Itoa(in))
	}
}

func WithCredentialSubject(in string) OptionFunc {
	return func(req gocoap.Message) {
		req.AddOption(gocoap.URIQuery, "subjectuuid="+in)
	}
}

func WithAccept(contentFormat gocoap.MediaType) OptionFunc {
	return func(req gocoap.Message) {
		req.SetOption(gocoap.Accept, contentFormat)
	}
}

func (c *Client) UpdateResource(
	ctx context.Context,
	href string,
	request interface{},
	response interface{},
	options ...OptionFunc,
) error {
	return c.UpdateResourceWithCodec(ctx, href, codecOcf.VNDOCFCBORCodec{}, request, response, options...)
}

func (c *Client) UpdateResourceWithCodec(
	ctx context.Context,
	href string,
	codec Codec,
	request interface{},
	response interface{},
	options ...OptionFunc,
) error {
	body, err := codec.Encode(request)
	if err != nil {
		return fmt.Errorf("could not encode the query %s: %v", href, err)
	}
	req, err := c.conn.NewPostRequest(href, codec.ContentFormat(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("could create request %s: %v", href, err)
	}
	for _, option := range options {
		option(req)
	}
	resp, err := c.conn.ExchangeWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("could not query %s: %v", href, err)
	}
	if resp.Code() != codes.Changed && resp.Code() != codes.Valid {
		return status.Error(resp, fmt.Errorf("request failed: %s", codecOcf.Dump(resp)))
	}
	if err := codec.Decode(resp, response); err != nil {
		return status.Error(resp, fmt.Errorf("could not decode the query %s: %v", href, err))
	}
	return nil
}

func (c *Client) GetResource(
	ctx context.Context,
	href string,
	response interface{},
	options ...OptionFunc,
) error {
	return c.GetResourceWithCodec(ctx, href, codecOcf.VNDOCFCBORCodec{}, response, options...)
}

func (c *Client) GetResourceWithCodec(
	ctx context.Context,
	href string,
	codec Codec,
	response interface{},
	options ...OptionFunc,
) error {
	req, err := c.conn.NewGetRequest(href)
	if err != nil {
		return fmt.Errorf("could create request %s: %v", href, err)
	}
	for _, option := range options {
		option(req)
	}
	resp, err := c.conn.ExchangeWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("could not query %s: %v", href, err)
	}
	if resp.Code() != codes.Content {
		return status.Error(resp, fmt.Errorf("request failed: %s", codecOcf.Dump(resp)))
	}
	if err := codec.Decode(resp, response); err != nil {
		return status.Error(resp, fmt.Errorf("could not decode the query %s: %v", href, err))
	}
	return nil
}

func (c *Client) DeleteResourceWithCodec(
	ctx context.Context,
	href string,
	codec Codec,
	response interface{},
	options ...OptionFunc,
) error {
	req, err := c.conn.NewDeleteRequest(href)
	if err != nil {
		return fmt.Errorf("could create request %s: %v", href, err)
	}
	for _, option := range options {
		option(req)
	}
	resp, err := c.conn.ExchangeWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("could not query %s: %v", href, err)
	}
	if resp.Code() != codes.Deleted {
		return status.Error(resp, fmt.Errorf("request failed: %s", codecOcf.Dump(resp)))
	}
	if err := codec.Decode(resp, response); err != nil {
		return status.Error(resp, fmt.Errorf("could not decode the query %s: %v", href, err))
	}
	return nil
}

func (c *Client) DeleteResource(
	ctx context.Context,
	href string,
	response interface{},
	options ...OptionFunc,
) error {
	return c.DeleteResourceWithCodec(ctx, href, codecOcf.VNDOCFCBORCodec{}, response, options...)
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// DecodeFunc can be used to pass in the data type that should be decoded.
type DecodeFunc func(interface{}) error

// ObservationHandler receives notifications from the observation request.
type ObservationHandler interface {
	Handle(ctx context.Context, client *gocoap.ClientConn, body DecodeFunc)
	Error(err error)
}

// Observe makes a CoAP observation request over a connection.
func (c *Client) Observe(
	ctx context.Context,
	href string,
	codec Codec,
	handler ObservationHandler,
	options ...OptionFunc,
) (*gocoap.Observation, error) {
	obs, err := c.conn.ObserveWithContext(ctx, href, observationHandler(codec, handler), options...)
	if err != nil {
		return nil, fmt.Errorf("could not observe %s: %v", href, err)
	}
	return obs, nil
}

func observationHandler(codec Codec, handler ObservationHandler) func(*gocoap.Request) {
	return func(req *gocoap.Request) {
		handler.Handle(req.Ctx, req.Client, decodeObservation(codec, req.Msg))
	}
}

func decodeObservation(codec Codec, m gocoap.Message) DecodeFunc {
	return func(body interface{}) error {
		if m.Code() != codes.Content {
			return status.Error(m, fmt.Errorf("observation failed: %s", codecOcf.Dump(m)))
		}
		if err := codec.Decode(m, body); err != nil {
			return status.Error(m, fmt.Errorf("could not decode observation: %v", err))
		}
		return nil
	}
}

func (c *Client) NewGetRequest(href string) (gocoap.Message, error) {
	return c.conn.NewGetRequest(href)
}

func (c *Client) ExchangeWithContext(ctx context.Context, req gocoap.Message) (gocoap.Message, error) {
	return c.conn.ExchangeWithContext(ctx, req)
}

func (c *Client) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

type CloseHandlerFunc = func(err error)

type OnCloseHandler struct {
	handlers map[int]CloseHandlerFunc
	nextId   int
	lock     sync.Mutex
}

func NewOnCloseHandler() *OnCloseHandler {
	return &OnCloseHandler{
		handlers: make(map[int]CloseHandlerFunc),
	}
}

func (h *OnCloseHandler) Add(onClose func(err error)) int {
	h.lock.Lock()
	defer h.lock.Unlock()
	v := h.nextId
	h.nextId++
	h.handlers[v] = onClose
	return v
}

func (h *OnCloseHandler) Remove(onCloseID int) {
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.handlers, onCloseID)
}

func (h *OnCloseHandler) getHandlers() []CloseHandlerFunc {
	h.lock.Lock()
	defer h.lock.Unlock()

	res := make([]func(error), 0, len(h.handlers))
	for _, ho := range h.handlers {
		res = append(res, ho)
	}
	return res

}

func (h *OnCloseHandler) OnClose(err error) {
	handlers := h.getHandlers()
	for _, ho := range handlers {
		ho(err)
	}
}

type ClientCloseHandler struct {
	*Client
	onClose *OnCloseHandler
}

func (c *ClientCloseHandler) RegisterCloseHandler(f CloseHandlerFunc) (closeHandlerID int) {
	return c.onClose.Add(f)
}

func (c *ClientCloseHandler) UnregisterCloseHandler(closeHandlerID int) {
	c.onClose.Remove(closeHandlerID)
}

func newClientCloseHandler(conn *gocoap.ClientConn, onClose *OnCloseHandler) *ClientCloseHandler {
	return &ClientCloseHandler{Client: NewClient(conn), onClose: onClose}
}

type DialOptionFunc func(gocoap.Client) gocoap.Client

func WithDialDisableTCPSignalMessages() DialOptionFunc {
	// Iotivity 1.3 close connection when it gets signal messages,
	// but Iotivity 2.0 requires them.
	return func(c gocoap.Client) gocoap.Client {
		c.DisableTCPSignalMessages = true
		return c
	}
}

func WithDialDisablePeerTCPSignalMessageCSMs() DialOptionFunc {
	return func(c gocoap.Client) gocoap.Client {
		// Disable processes Capabilities and Settings Messages from client - iotivity sends max message size without blockwise.
		c.DisablePeerTCPSignalMessageCSMs = true
		return c
	}
}

func DialUDP(ctx context.Context, addr string, opts ...DialOptionFunc) (*ClientCloseHandler, error) {
	h := NewOnCloseHandler()
	client := gocoap.Client{Net: "udp", NotifySessionEndFunc: h.OnClose}
	for _, o := range opts {
		client = o(client)
	}
	c, err := client.DialWithContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	return newClientCloseHandler(c, h), nil
}

func DialTCP(ctx context.Context, addr string, opts ...DialOptionFunc) (*ClientCloseHandler, error) {
	h := NewOnCloseHandler()
	client := gocoap.Client{Net: "tcp", NotifySessionEndFunc: h.OnClose}
	for _, o := range opts {
		client = o(client)
	}
	c, err := client.DialWithContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	return newClientCloseHandler(c, h), nil
}

func createVerifyPeerCertificate(cas []*x509.Certificate, verifyPeerCertificate func(verifyPeerCertificate *x509.Certificate) error) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	caPool := security.NewDefaultCertPool(cas)

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("empty certificates chain")
		}
		intermediateCAPool := x509.NewCertPool()
		var certificate *x509.Certificate
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}
		for _, cert := range certs[1:] {
			intermediateCAPool.AddCert(cert)
		}
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         caPool,
			Intermediates: intermediateCAPool,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return err
		}
		if verifyPeerCertificate(certificate) != nil {
			return err
		}
		return nil
	}
}

func DialTCPSecure(ctx context.Context, addr string, cert tls.Certificate, cas []*x509.Certificate, verifyPeerCertificate func(verifyPeerCertificate *x509.Certificate) error, opts ...DialOptionFunc) (*ClientCloseHandler, error) {
	h := NewOnCloseHandler()
	tlsConfig := tls.Config{
		InsecureSkipVerify:    true,
		Certificates:          []tls.Certificate{cert},
		VerifyPeerCertificate: createVerifyPeerCertificate(cas, verifyPeerCertificate),
	}
	client := gocoap.Client{Net: "tcp-tls", NotifySessionEndFunc: h.OnClose,
		TLSConfig: &tlsConfig,
	}
	for _, o := range opts {
		client = o(client)
	}
	c, err := client.DialWithContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	return newClientCloseHandler(c, h), nil
}

func DialUDPSecure(ctx context.Context, addr string, cert tls.Certificate, cas []*x509.Certificate, verifyPeerCertificate func(verifyPeerCertificate *x509.Certificate) error, opts ...DialOptionFunc) (*ClientCloseHandler, error) {
	h := NewOnCloseHandler()
	caPool := x509.NewCertPool()
	for _, ca := range cas {
		caPool.AddCert(ca)
	}

	log := logging.NewDefaultLoggerFactory()
	log.DefaultLogLevel = logging.LogLevelTrace

	tlsConfig := dtls.Config{
		LoggerFactory:         log,
		InsecureSkipVerify:    true,
		Certificates:          []tls.Certificate{cert},
		VerifyPeerCertificate: createVerifyPeerCertificate(cas, verifyPeerCertificate),
	}
	client := gocoap.Client{Net: "udp-dtls", NotifySessionEndFunc: h.OnClose,
		DTLSConfig: &tlsConfig,
	}
	for _, o := range opts {
		client = o(client)
	}
	c, err := client.DialWithContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	return newClientCloseHandler(c, h), nil
}
