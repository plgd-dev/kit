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

// getHTTPSClient gets an HTTPS client configured to trust our CA's root
// certificate.
func getHTTPSClient(cas []*x509.Certificate) (*http.Client, error) {
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

func (l *LegoUser) GetEmail() string {
	return l.email
}

func (l *LegoUser) GetRegistration() *registration.Resource {
	return l.registration
}

func (l *LegoUser) GetPrivateKey() crypto.PrivateKey {
	return l.key
}

// Uses techniques from https://diogomonica.com/2017/01/11/hitless-tls-certificate-rotation-in-go/
// to automatically rotate certificates when they're renewed.

// CertManager manages ACME certificate renewals and makes it easy to use
// certificates with the tls package.`
type CertManager struct {
	sync.RWMutex
	acmeClient  *lego.Client
	certificate *tls.Certificate
	cas         *x509.CertPool
	domains     []string
	leaf        *x509.Certificate
	resource    *certificate.Resource
	done        chan struct{}
	doneWg      sync.WaitGroup
}

// NewCertManager configures an ACME client, creates & registers a new ACME
// user. After creating a client you must call ObtainCertificate and
// RenewCertificate yourself.
func NewCertManager(cas []*x509.Certificate, caDirURL, email string, domains []string, tickFrequency time.Duration) (*CertManager, error) {
	// Create a new ACME user with a new key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	user := &LegoUser{
		email: email,
		key:   key,
	}

	// Get an HTTPS client configured to trust our root certificate.
	httpClient, err := getHTTPSClient(cas)
	if err != nil {
		return nil, err
	}

	// Create a configuration using our HTTPS client, ACME server, user details.
	config := &lego.Config{
		CADirURL:   caDirURL,
		User:       user,
		HTTPClient: httpClient,
		Certificate: lego.CertificateConfig{
			KeyType: certcrypto.RSA2048,
			Timeout: 30 * time.Second,
		},
	}

	// Create an ACME client and configure use of `http-01` challenge
	acmeClient, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	err = acmeClient.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	if err != nil {
		log.Fatal(err)
	}

	// Register our ACME user
	registration, err := acmeClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	user.registration = registration

	acm := &CertManager{
		acmeClient: acmeClient,
		domains:    domains,
	}

	err = acm.ObtainCertificate()
	if err != nil {
		return nil, fmt.Errorf("cannot load certificate and key: %v", err)
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
			if a.NeedsRenewal() {
				log.Debug("Renewing certificate")
				err := a.RenewCertificate()
				if err != nil {
					log.Debug("Error loading certificate and key", err)
				} else {
					leaf := a.GetLeaf()
					log.Debug("Renewed certificate: %s [%s - %s]\n", leaf.Subject, leaf.NotBefore, leaf.NotAfter)
					log.Debug("Next renewal at %s (%s)\n", nextRenewal, nextRenewal.Sub(time.Now()))
				}
			} else {
				log.Debug("Waiting to renew at %s (%s)\n", nextRenewal, nextRenewal.Sub(time.Now()))
			}
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

	resource, err := a.acmeClient.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	return a.switchCertificate(resource)
}

// RenewCertificate renews an existing certificate using ACME. Not thread safe.
func (a *CertManager) RenewCertificate() error {
	resource, err := a.acmeClient.Certificate.Renew(*a.resource, true, false)
	if err != nil {
		return err
	}

	return a.switchCertificate(resource)
}

// GetCertificate locks around returning a tls.Certificate; use as tls.Config.GetCertificate.
func (a *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.RLock()
	defer a.RUnlock()
	return a.certificate, nil
}

// GetClientCertificate locks around returning a tls.ClientCertificate; use as tls.Config.GetClientCertificate.
func (a *CertManager) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	a.RLock()
	defer a.RUnlock()
	return a.certificate, nil
}

// GetCertificateAuthorities returns certificates authorities
func (a *CertManager) GetCertificateAuthorities() *x509.CertPool {
	return a.cas
}

// GetLeaf returns the currently valid leaf x509.Certificate
func (a *CertManager) GetLeaf() x509.Certificate {
	a.RLock()
	defer a.RUnlock()
	return *a.leaf
}

func (a *CertManager) GetClientTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:                  a.GetCertificateAuthorities(),
		GetClientCertificate:     a.GetClientCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
}
func (a *CertManager) GetServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientCAs:      a.GetCertificateAuthorities(),
		GetCertificate: a.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAndVerifyClientCert,
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

	a.Lock()
	defer a.Unlock()
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
	CAPool        string        `envconfig:"ROOT_CERTIFICATE_AUTHORITY" long:"ca" env:"ROOT_CERTIFICATE_AUTHORITY" description:"file path to the root certificate"`
	CADirURL      string        `envconfig:"ACME_DIRECTORY_URL" long:"acme-directory-url"  env:"ACME_DIRECTORY_URL" description:"the ACME directory URL for your ACME server"`
	Domains       []string      `envconfig:"DOMAINS" long:"domains" env:"DOMAINS" description:"the domain's names for which we'll be getting a certificate"`
	Email         string        `envconfig:"EMAIL" long:"email" env:"EMAIL" description:"the email address to use during ACME registration"`
	TickFrequency time.Duration `envconfig:"TICK_FREQUENCY" long:"tick-frequency" env:"TICK_FREQUENCY" description:"how frequently we should check whether our cert needs renewal" default:"15s"`
}

// NewCertManagerFromConfiguration creates certificate manager from config.
func NewCertManagerFromConfiguration(config Config) (*CertManager, error) {
	var cas []*x509.Certificate
	if config.CAPool != "" {
		certs, err := security.LoadX509(config.CAPool)
		if err != nil {
			return nil, fmt.Errorf("cannot load certificate authorities from '%v': %v", config.CAPool, err)
		}
		cas = certs
	}
	return NewCertManager(cas, config.CADirURL, config.Email, config.Domains, config.TickFrequency)
}
