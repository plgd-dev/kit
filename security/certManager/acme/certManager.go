package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge/http01"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/go-ocf/kit/log"
	"github.com/go-ocf/kit/security"
	"golang.org/x/net/http2"
)

// GetHTTPSClient gets an HTTPS client configured to trust our CA's root
// certificate.
func GetHTTPSClient(cas []*x509.Certificate) (*http.Client, error) {
	tlsCfg := security.NewDefaultTLSConfig(cas)

	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, errors.New("Error configuring transport")
	}
	return &http.Client{
		Transport: tr,
	}, nil
}

// LegoUser implements registration.User, required by lego.
type LegoUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func NewUser(email string, key crypto.PrivateKey) *LegoUser {
	return &LegoUser{
		email: email,
		key:   key,
	}
}

func (l *LegoUser) SetRegistration(r *registration.Resource) {
	l.registration = r
}

func (l *LegoUser) GetEmail() string {
	return l.email
}

func (l *LegoUser) GetRegistration() *registration.Resource {
	return l.registration
}

func (l *LegoUser) GetPrivateKey() crypto.PrivateKey {
	return l.key
}

type Certifier = interface {
	Obtain(request certificate.ObtainRequest) (*certificate.Resource, error)
	Renew(certRes certificate.Resource, bundle, mustStaple bool) (*certificate.Resource, error)
}

type Client = interface {
	Certificate() Certifier
}

// Uses techniques from https://diogomonica.com/2017/01/11/hitless-tls-certificate-rotation-in-go/
// to automatically rotate certificates when they're renewed.

// CertManager manages ACME certificate renewals and makes it easy to use
// certificates with the tls package.`
type CertManager struct {
	mutex                   sync.Mutex
	acmeClient              Client
	certificate             *tls.Certificate
	cas                     *x509.CertPool
	domains                 []string
	leaf                    *x509.Certificate
	resource                *certificate.Resource
	done                    chan struct{}
	doneWg                  sync.WaitGroup
	verifyClientCertificate tls.ClientAuthType
}

// NewCertManager configures an ACME client, creates & registers a new ACME
// user. After creating a client you must call ObtainCertificate and
// RenewCertificate yourself.
func NewCertManager(cas []*x509.Certificate, disableVerifyClientCertificate bool, domains []string, tickFrequency time.Duration, acmeClient Client) (*CertManager, error) {
	tlsVerifyClientCertificate := tls.RequireAndVerifyClientCert
	if disableVerifyClientCertificate {
		tlsVerifyClientCertificate = tls.NoClientCert
	}
	acm := &CertManager{
		acmeClient:              acmeClient,
		domains:                 domains,
		cas:                     security.NewDefaultCertPool(cas),
		verifyClientCertificate: tlsVerifyClientCertificate,
	}

	err := acm.ObtainCertificate()
	if err != nil {
		return nil, fmt.Errorf("cannot load certificate and key: %w", err)
	}

	if tickFrequency > 0 {
		acm.done = make(chan struct{})
		acm.doneWg.Add(1)
		go acm.autoRenewCert(tickFrequency)
	}

	return acm, nil
}

func (a *CertManager) autoRenewCert(tickFrequency time.Duration) {
	ticker := time.NewTicker(tickFrequency)
	defer a.doneWg.Done()
	defer ticker.Stop()
	for {
		nextRenewal := a.NextRenewal()
		select {
		case <-ticker.C:
			if !a.NeedsRenewal() {
				continue
			}
			err := a.RenewCertificate()
			if err != nil {
				log.Errorf("Error loading certificate and key", err)
				continue
			}
			leaf := a.GetLeaf()
			log.Infof("Renewed certificate: %s [%s - %s]\n", leaf.Subject, leaf.NotBefore, leaf.NotAfter)
			log.Infof("Next renewal at %s (%s)\n", nextRenewal, nextRenewal.Sub(time.Now()))
		case <-a.done:
			return
		}
	}
}

// ObtainCertificate gets a new certificate using ACME. Not thread safe.
func (a *CertManager) ObtainCertificate() error {
	request := certificate.ObtainRequest{
		Domains: a.domains,
		Bundle:  true,
	}

	resource, err := a.acmeClient.Certificate().Obtain(request)
	if err != nil {
		return err
	}

	return a.switchCertificate(resource)
}

// RenewCertificate renews an existing certificate using ACME. Not thread safe.
func (a *CertManager) RenewCertificate() error {
	resource, err := a.acmeClient.Certificate().Renew(*a.resource, true, false)
	if err != nil {
		return err
	}

	// renew via CSR doesn't fill private key
	if len(resource.PrivateKey) == 0 {
		resource.PrivateKey = a.resource.PrivateKey
	}

	return a.switchCertificate(resource)
}

// GetCertificate locks around returning a tls.Certificate; use as tls.Config.GetCertificate.
func (a *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.certificate, nil
}

// GetClientCertificate locks around returning a tls.ClientCertificate; use as tls.Config.GetClientCertificate.
func (a *CertManager) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.certificate, nil
}

// GetCertificateAuthorities returns certificates authorities
func (a *CertManager) GetCertificateAuthorities() *x509.CertPool {
	return a.cas
}

// GetLeaf returns the currently valid leaf x509.Certificate
func (a *CertManager) GetLeaf() *x509.Certificate {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.leaf
}

func (a *CertManager) GetClientTLSConfig() tls.Config {
	return tls.Config{
		RootCAs:                  a.GetCertificateAuthorities(),
		GetClientCertificate:     a.GetClientCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}
func (a *CertManager) GetServerTLSConfig() tls.Config {
	return tls.Config{
		ClientCAs:      a.GetCertificateAuthorities(),
		GetCertificate: a.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     a.verifyClientCertificate,
	}
}

// NextRenewal returns when the certificate will be 2/3 of the way to expiration.
func (a *CertManager) NextRenewal() time.Time {
	leaf := a.GetLeaf()
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore).Seconds()
	return leaf.NotBefore.Add(time.Duration(lifetime*2/3) * time.Second)
}

// NeedsRenewal returns true if the certificate's age is more than 2/3 it's
// lifetime.
func (a *CertManager) NeedsRenewal() bool {
	return time.Now().After(a.NextRenewal())
}

func (a *CertManager) switchCertificate(newResource *certificate.Resource) error {
	// The certificate.Resource represents our certificate as a PEM-encoded
	// bundle of bytes. Let's process it. First create a tls.Certificate
	// for use with the tls package.
	crt, err := tls.X509KeyPair(newResource.Certificate, newResource.PrivateKey)
	if err != nil {
		fmt.Printf("newResource.Certificate %v newResource.PrivateKey %v\n", newResource.Certificate, newResource.PrivateKey)
		return err
	}

	// Now create an x509.Certificate so we can figure out when the cert
	// expires. Note that the first certificate in the bundle is the leaf.
	// Go ahead and set crt.Leaf as an optimization.
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return err
	}
	crt.Leaf = leaf

	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.resource = newResource
	a.certificate = &crt
	a.leaf = leaf

	return nil
}

// Close terminates autorenew goroutine.
func (a *CertManager) Close() {
	if a.done != nil {
		close(a.done)
		a.doneWg.Wait()
	}
}

// Config set configuration.
type Config struct {
	CAPool                         string        `envconfig:"CA_POOL" env:"CA_POOL" long:"ca" description:"file path to the root certificate in PEM format"`
	CADirURL                       string        `envconfig:"DIRECTORY_URL" env:"DIRECTORY_URL" long:"acme-directory-url" description:"the ACME directory URL for your ACME server"`
	Domains                        []string      `envconfig:"DOMAINS" env:"DOMAINS" long:"domains" description:"the domain's names for which we'll be getting a certificate"`
	Email                          string        `envconfig:"REGISTRATION_EMAIL" env:"REGISTRATION_EMAIL" long:"email" description:"the email address to use during ACME registration"`
	TickFrequency                  time.Duration `envconfig:"TICK_FREQUENCY" env:"TICK_FREQUENCY" long:"tick-frequency" description:"how frequently we should check whether our cert needs renewal" default:"15s"`
	ChallengeListenPort            uint16        `envconfig:"CHALLENGE_LISTEN_PORT" env:"CHALLENGE_LISTEN_PORT" long:"challenge-listen-port" default:"80" description:"listen port to accept challenge requests from acme server"`
	DisableVerifyClientCertificate bool          `envconfig:"DISABLE_VERIFY_CLIENT_CERTIFICATE" env:"DISABLE_VERIFY_CLIENT_CERTIFICATE" long:"disable-verify-client-certificate" description:"disable verify client ceritificate"`
}

type legoClient struct {
	c *lego.Client
}

func (c *legoClient) Certificate() Certifier {
	return c.c.Certificate
}

// NewCertManagerFromConfiguration creates certificate manager from config.
func NewCertManagerFromConfiguration(config Config) (*CertManager, error) {
	var cas []*x509.Certificate
	if config.CAPool != "" {
		certs, err := security.LoadX509(config.CAPool)
		if err != nil {
			return nil, fmt.Errorf("cannot load certificate authorities from '%v': %w", config.CAPool, err)
		}
		cas = certs
	}

	if config.ChallengeListenPort == 0 {
		return nil, fmt.Errorf("invalid ChallengeListenPort")
	}

	// Create a new ACME user with a new key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	user := NewUser(config.Email, key)

	// Get an HTTPS client configured to trust our root certificate.
	httpClient, err := GetHTTPSClient(cas)
	if err != nil {
		return nil, err
	}

	// Create a configuration using our HTTPS client, ACME server, user details.
	cfg := &lego.Config{
		CADirURL:   config.CADirURL,
		User:       user,
		HTTPClient: httpClient,
		Certificate: lego.CertificateConfig{
			KeyType: certcrypto.EC256,
			Timeout: 30 * time.Second,
		},
	}

	// Create an ACME client and configure use of `http-01` challenge
	acmeClient, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	err = acmeClient.Challenge.SetHTTP01Provider(http01.NewProviderServer("", strconv.Itoa(int(config.ChallengeListenPort))))
	if err != nil {
		return nil, err
	}

	// Register our ACME user
	registration, err := acmeClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	user.SetRegistration(registration)

	return NewCertManager(cas, config.DisableVerifyClientCertificate, config.Domains, config.TickFrequency, &legoClient{acmeClient})
}
