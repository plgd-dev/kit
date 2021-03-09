package coap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	uuid "github.com/gofrs/uuid"
	piondtls "github.com/pion/dtls/v2"
	"github.com/plgd-dev/go-coap/v2/dtls"
	"github.com/plgd-dev/go-coap/v2/net/monitor/inactivity"
	"github.com/plgd-dev/go-coap/v2/tcp"
	"github.com/plgd-dev/go-coap/v2/udp"

	"github.com/plgd-dev/go-coap/v2/message"
	"github.com/plgd-dev/go-coap/v2/message/codes"
	codecOcf "github.com/plgd-dev/kit/codec/ocf"
	"github.com/plgd-dev/kit/net/coap/status"
)

type Observation = interface {
	Cancel(context.Context) error
}

type ClientConn = interface {
	Post(ctx context.Context, path string, contentFormat message.MediaType, payload io.ReadSeeker, opts ...message.Option) (*message.Message, error)
	Get(ctx context.Context, path string, opts ...message.Option) (*message.Message, error)
	Delete(ctx context.Context, path string, opts ...message.Option) (*message.Message, error)
	Observe(ctx context.Context, path string, observeFunc func(notification *message.Message), opts ...message.Option) (Observation, error)
	RemoteAddr() net.Addr
	Close() error
	Context() context.Context
}

type Client struct {
	conn ClientConn
}

// Codec encodes/decodes according to the CoAP content format/media type.
type Codec interface {
	ContentFormat() message.MediaType
	Encode(v interface{}) ([]byte, error)
	Decode(m *message.Message, v interface{}) error
}

// GetRawCodec returns raw codec depends on contentFormat.
func GetRawCodec(contentFormat message.MediaType) Codec {
	if contentFormat == message.AppCBOR || contentFormat == message.AppOcfCbor {
		return codecOcf.RawVNDOCFCBORCodec{}
	}
	return codecOcf.NoCodec{
		MediaType: uint16(contentFormat),
	}
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
		return "", fmt.Errorf("invalid subject common name %v: %w", cert.Subject.CommonName, err)
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

func NewClient(conn ClientConn) *Client {
	return &Client{conn: conn}
}

type OptionFunc = func(message.Options) message.Options

func WithInterface(in string) OptionFunc {
	return func(opts message.Options) message.Options {
		v := "if=" + in
		buf := make([]byte, len(v))
		opts, _, _ = opts.AddString(buf, message.URIQuery, v)
		return opts
	}
}

func WithResourceType(in string) OptionFunc {
	return func(opts message.Options) message.Options {
		v := "rt=" + in
		buf := make([]byte, len(v))
		opts, _, _ = opts.AddString(buf, message.URIQuery, v)
		return opts
	}
}

func WithInstanceID(in int) OptionFunc {
	return func(opts message.Options) message.Options {
		v := "ins=" + strconv.Itoa(in)
		buf := make([]byte, len(v))
		opts, _, _ = opts.AddString(buf, message.URIQuery, v)
		return opts
	}
}

func WithDeviceID(in string) OptionFunc {
	return func(opts message.Options) message.Options {
		v := "di=" + in
		buf := make([]byte, len(v))
		opts, _, _ = opts.AddString(buf, message.URIQuery, v)
		return opts
	}
}

func WithCredentialId(in int) OptionFunc {
	return func(opts message.Options) message.Options {
		v := "credid=" + strconv.Itoa(in)
		buf := make([]byte, len(v))
		opts, _, _ = opts.AddString(buf, message.URIQuery, v)
		return opts
	}
}

func WithCredentialSubject(in string) OptionFunc {
	return func(opts message.Options) message.Options {
		v := "subjectuuid=" + in
		buf := make([]byte, len(v))
		opts, _, _ = opts.AddString(buf, message.URIQuery, v)
		return opts
	}
}

func WithAccept(contentFormat message.MediaType) OptionFunc {
	return func(opts message.Options) message.Options {
		buf := make([]byte, 4)
		opts, _, _ = opts.SetUint32(buf, message.Accept, uint32(contentFormat))
		return opts
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
		return fmt.Errorf("could not encode the query %s: %w", href, err)
	}
	opts := make(message.Options, 0, 4)
	for _, o := range options {
		opts = o(opts)
	}

	resp, err := c.conn.Post(ctx, href, codec.ContentFormat(), bytes.NewReader(body), opts...)
	if err != nil {
		return fmt.Errorf("could create request %s: %w", href, err)
	}
	if err != nil {
		return fmt.Errorf("could not query %s: %w", href, err)
	}
	if resp.Code != codes.Changed && resp.Code != codes.Valid {
		return status.Error(resp, fmt.Errorf("request failed: %s", codecOcf.Dump(resp)))
	}
	if err := codec.Decode(resp, response); err != nil {
		return status.Error(resp, fmt.Errorf("could not decode the query %s: %w", href, err))
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
	opts := make(message.Options, 0, 4)
	for _, o := range options {
		opts = o(opts)
	}
	resp, err := c.conn.Get(ctx, href, opts...)
	if err != nil {
		return fmt.Errorf("could not query %s: %w", href, err)
	}
	if resp.Code != codes.Content {
		return status.Error(resp, fmt.Errorf("request failed: %s", codecOcf.Dump(resp)))
	}
	if err := codec.Decode(resp, response); err != nil {
		return status.Error(resp, fmt.Errorf("could not decode the query %s: %w", href, err))
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
	opts := make(message.Options, 0, 4)
	for _, o := range options {
		opts = o(opts)
	}
	resp, err := c.conn.Delete(ctx, href, opts...)
	if err != nil {
		return fmt.Errorf("could not query %s: %w", href, err)
	}
	if resp.Code != codes.Deleted {
		return status.Error(resp, fmt.Errorf("request failed: %s", codecOcf.Dump(resp)))
	}
	if err := codec.Decode(resp, response); err != nil {
		return status.Error(resp, fmt.Errorf("could not decode the query %s: %w", href, err))
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
	Handle(client *Client, body DecodeFunc)
	Error(err error)
}

// Observe makes a CoAP observation request over a connection.
func (c *Client) Observe(
	ctx context.Context,
	href string,
	codec Codec,
	handler ObservationHandler,
	options ...OptionFunc,
) (Observation, error) {
	opts := make(message.Options, 0, 4)
	for _, o := range options {
		opts = o(opts)
	}
	obs, err := c.conn.Observe(ctx, href, observationHandler(c, codec, handler), opts...)
	if err != nil {
		return nil, fmt.Errorf("could not observe %s: %w", href, err)
	}
	return obs, nil
}

func observationHandler(c *Client, codec Codec, handler ObservationHandler) func(*message.Message) {
	return func(msg *message.Message) {
		handler.Handle(c, decodeObservation(codec, msg))
	}
}

func decodeObservation(codec Codec, m *message.Message) DecodeFunc {
	return func(body interface{}) error {
		if m.Code != codes.Content {
			return status.Error(m, fmt.Errorf("observation failed: %s", codecOcf.Dump(m)))
		}
		if err := codec.Decode(m, body); err != nil {
			return status.Error(m, fmt.Errorf("could not decode observation: %w", err))
		}
		return nil
	}
}

func (c *Client) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Client) Context() context.Context {
	return c.conn.Context()
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

func newClientCloseHandler(conn ClientConn, onClose *OnCloseHandler) *ClientCloseHandler {
	return &ClientCloseHandler{Client: NewClient(conn), onClose: onClose}
}

type dialOptions struct {
	DisableTCPSignalMessageCSM      bool
	DisablePeerTCPSignalMessageCSMs bool
	KeepaliveTimeout                time.Duration
	errors                          func(err error)
	maxMessageSize                  int
	dialer                          *net.Dialer
	heartBeat                       time.Duration
}

type DialOptionFunc func(dialOptions) dialOptions

func WithDialDisableTCPSignalMessageCSM() DialOptionFunc {
	// Iotivity 1.3 close connection when it gets signal messages,
	// but Iotivity 2.0 requires them.
	return func(c dialOptions) dialOptions {
		c.DisableTCPSignalMessageCSM = true
		return c
	}
}

func WithDialDisablePeerTCPSignalMessageCSMs() DialOptionFunc {
	return func(c dialOptions) dialOptions {
		// Disable processes Capabilities and Settings Messages from client - iotivity sends max message size without blockwise.
		c.DisablePeerTCPSignalMessageCSMs = true
		return c
	}
}

// WithKeepAlive sets a policy that detects dropped connections within the connTimeout limit
// while attempting to make 3 pings during that period.
func WithKeepAlive(connectionTimeout time.Duration) DialOptionFunc {
	return func(c dialOptions) dialOptions {
		c.KeepaliveTimeout = connectionTimeout
		return c
	}
}

func WithErrors(errors func(err error)) DialOptionFunc {
	return func(c dialOptions) dialOptions {
		c.errors = errors
		return c
	}
}

func WithMaxMessageSize(maxMessageSize int) DialOptionFunc {
	return func(c dialOptions) dialOptions {
		c.maxMessageSize = maxMessageSize
		return c
	}
}

func WithDialer(dialer *net.Dialer) DialOptionFunc {
	return func(c dialOptions) dialOptions {
		c.dialer = dialer
		return c
	}
}

func WithHeartBeat(heartBeat time.Duration) DialOptionFunc {
	return func(c dialOptions) dialOptions {
		c.heartBeat = heartBeat
		return c
	}
}

func DialUDP(ctx context.Context, addr string, opts ...DialOptionFunc) (*ClientCloseHandler, error) {
	h := NewOnCloseHandler()
	var cfg dialOptions
	for _, o := range opts {
		cfg = o(cfg)
	}
	dopts := make([]udp.DialOption, 0, 4)
	if cfg.KeepaliveTimeout != 0 {
		dopts = append(dopts, udp.WithKeepAlive(3, cfg.KeepaliveTimeout/3, func(cc inactivity.ClientConn) {
			cc.Close()
			cfg.errors(fmt.Errorf("keep alive was reached fail limit:: closing connection"))
		}))
	}
	if cfg.errors != nil {
		dopts = append(dopts, udp.WithErrors(cfg.errors))
	}
	if cfg.maxMessageSize > 0 {
		dopts = append(dopts, udp.WithMaxMessageSize(cfg.maxMessageSize))
	}
	if cfg.heartBeat > 0 {
		dopts = append(dopts, udp.WithHeartBeat(cfg.heartBeat))
	}
	if cfg.dialer != nil {
		dopts = append(dopts, udp.WithDialer(cfg.dialer))
	} else {
		deadline, ok := ctx.Deadline()
		if ok {
			dopts = append(dopts, udp.WithDialer(&net.Dialer{
				Timeout: deadline.Sub(time.Now()),
			}))
		}
	}
	c, err := udp.Dial(addr, dopts...)
	if err != nil {
		return nil, err
	}
	c.AddOnClose(func() {
		h.OnClose(nil)
	})
	return newClientCloseHandler(c.Client(), h), nil
}

func DialTCP(ctx context.Context, addr string, opts ...DialOptionFunc) (*ClientCloseHandler, error) {
	h := NewOnCloseHandler()
	var cfg dialOptions
	for _, o := range opts {
		cfg = o(cfg)
	}
	dopts := make([]tcp.DialOption, 0, 4)
	if cfg.KeepaliveTimeout != 0 {
		dopts = append(dopts, tcp.WithKeepAlive(3, cfg.KeepaliveTimeout/3, func(cc inactivity.ClientConn) {
			cc.Close()
			cfg.errors(fmt.Errorf("keep alive was reached fail limit:: closing connection"))
		}))
	}
	if cfg.DisablePeerTCPSignalMessageCSMs {
		dopts = append(dopts, tcp.WithDisablePeerTCPSignalMessageCSMs())
	}
	if cfg.DisableTCPSignalMessageCSM {
		dopts = append(dopts, tcp.WithDisableTCPSignalMessageCSM())
	}
	if cfg.errors != nil {
		dopts = append(dopts, tcp.WithErrors(cfg.errors))
	}
	if cfg.maxMessageSize > 0 {
		dopts = append(dopts, tcp.WithMaxMessageSize(cfg.maxMessageSize))
	}
	if cfg.heartBeat > 0 {
		dopts = append(dopts, tcp.WithHeartBeat(cfg.heartBeat))
	}
	if cfg.dialer != nil {
		dopts = append(dopts, tcp.WithDialer(cfg.dialer))
	} else {
		deadline, ok := ctx.Deadline()
		if ok {
			dopts = append(dopts, tcp.WithDialer(&net.Dialer{
				Timeout: deadline.Sub(time.Now()),
			}))
		}
	}
	c, err := tcp.Dial(addr, dopts...)
	if err != nil {
		return nil, err
	}
	c.AddOnClose(func() {
		h.OnClose(nil)
	})
	return newClientCloseHandler(c.Client(), h), nil
}

func NewVerifyPeerCertificate(rootCAs *x509.CertPool, verifyPeerCertificate func(verifyPeerCertificate *x509.Certificate) error) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("empty certificates chain")
		}
		intermediateCAPool := x509.NewCertPool()
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
			Roots:         rootCAs,
			Intermediates: intermediateCAPool,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return err
		}
		if verifyPeerCertificate == nil {
			return nil
		}
		if verifyPeerCertificate(certs[0]) != nil {
			return err
		}
		return nil
	}
}

func DialTCPSecure(ctx context.Context, addr string, tlsCfg *tls.Config, opts ...DialOptionFunc) (*ClientCloseHandler, error) {
	h := NewOnCloseHandler()
	var cfg dialOptions
	for _, o := range opts {
		cfg = o(cfg)
	}
	dopts := make([]tcp.DialOption, 0, 4)
	dopts = append(dopts, tcp.WithTLS(tlsCfg))
	if cfg.KeepaliveTimeout != 0 {
		dopts = append(dopts, tcp.WithKeepAlive(3, cfg.KeepaliveTimeout/3, func(cc inactivity.ClientConn) {
			cc.Close()
			cfg.errors(fmt.Errorf("keep alive was reached fail limit:: closing connection"))
		}))
	}
	if cfg.DisablePeerTCPSignalMessageCSMs {
		dopts = append(dopts, tcp.WithDisablePeerTCPSignalMessageCSMs())
	}
	if cfg.DisableTCPSignalMessageCSM {
		dopts = append(dopts, tcp.WithDisableTCPSignalMessageCSM())
	}
	if cfg.errors != nil {
		dopts = append(dopts, tcp.WithErrors(cfg.errors))
	}
	if cfg.maxMessageSize > 0 {
		dopts = append(dopts, tcp.WithMaxMessageSize(cfg.maxMessageSize))
	}
	if cfg.heartBeat > 0 {
		dopts = append(dopts, tcp.WithHeartBeat(cfg.heartBeat))
	}
	if cfg.dialer != nil {
		dopts = append(dopts, tcp.WithDialer(cfg.dialer))
	} else {
		deadline, ok := ctx.Deadline()
		if ok {
			dopts = append(dopts, tcp.WithDialer(&net.Dialer{
				Timeout: deadline.Sub(time.Now()),
			}))
		}
	}
	c, err := tcp.Dial(addr, dopts...)
	if err != nil {
		return nil, err
	}
	c.AddOnClose(func() {
		h.OnClose(nil)
	})
	return newClientCloseHandler(c.Client(), h), nil
}

func DialUDPSecure(ctx context.Context, addr string, dtlsCfg *piondtls.Config, opts ...DialOptionFunc) (*ClientCloseHandler, error) {
	h := NewOnCloseHandler()

	if dtlsCfg.ConnectContextMaker == nil {
		dtlsCfg.ConnectContextMaker = func() (context.Context, func()) {
			return ctx, func() {}
		}
	}

	var cfg dialOptions
	for _, o := range opts {
		cfg = o(cfg)
	}
	dopts := make([]dtls.DialOption, 0, 4)
	if cfg.KeepaliveTimeout != 0 {
		dopts = append(dopts, dtls.WithKeepAlive(3, cfg.KeepaliveTimeout/3, func(cc inactivity.ClientConn) {
			cc.Close()
			cfg.errors(fmt.Errorf("keep alive was reached fail limit:: closing connection"))
		}))
	}
	if cfg.errors != nil {
		dopts = append(dopts, dtls.WithErrors(cfg.errors))
	}
	if cfg.maxMessageSize > 0 {
		dopts = append(dopts, dtls.WithMaxMessageSize(cfg.maxMessageSize))
	}
	if cfg.heartBeat > 0 {
		dopts = append(dopts, dtls.WithHeartBeat(cfg.heartBeat))
	}
	if cfg.dialer != nil {
		dopts = append(dopts, dtls.WithDialer(cfg.dialer))
	} else {
		deadline, ok := ctx.Deadline()
		if ok {
			dopts = append(dopts, dtls.WithDialer(&net.Dialer{
				Timeout: deadline.Sub(time.Now()),
			}))
		}
	}
	c, err := dtls.Dial(addr, dtlsCfg, dopts...)
	if err != nil {
		return nil, err
	}
	c.AddOnClose(func() {
		h.OnClose(nil)
	})
	return newClientCloseHandler(c.Client(), h), nil
}
