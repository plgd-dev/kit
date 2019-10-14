package lego

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/acme"
	"github.com/go-acme/lego/acme/api"
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge"
	"github.com/go-acme/lego/log"
	"github.com/go-acme/lego/platform/wait"
	"golang.org/x/crypto/ocsp"
)

type resolverInternal interface {
	Solve(authorizations []acme.Authorization) error
}

// Certifier A service to obtain/renew/revoke certificates.
type Certifier struct {
	core      *api.Core
	resolver  resolverInternal
	options   certificate.CertifierOptions
	certifier *certificate.Certifier
}

// NewCertifier creates a Certifier.
// Only difference is that the domains are inferred only from the SubjectAltNames for ObtainCSR.
// This cause that the certifier is not compatible with let's encrypt.
func NewCertifier(core *api.Core, resolver resolverInternal, options certificate.CertifierOptions) *Certifier {
	certifier := certificate.NewCertifier(core, resolver, options)

	return &Certifier{
		core:      core,
		resolver:  resolver,
		options:   options,
		certifier: certifier,
	}
}

// Obtain tries to obtain a single certificate using all domains passed into it.
//
// This function will never return a partial certificate.
// If one domain in the list fails, the whole certificate will fail.
func (c *Certifier) Obtain(request certificate.ObtainRequest) (*certificate.Resource, error) {
	return c.certifier.Obtain(request)
}

func containsSAN(domains []string, sanName string) bool {
	for _, existingName := range domains {
		if existingName == sanName {
			return true
		}
	}
	return false
}

// extract domains only from SAN
func extractDomainsCSR(csr *x509.CertificateRequest) []string {
	domains := make([]string, 0, 4)

	// loop over the SubjectAltName DNS names
	for _, sanName := range csr.DNSNames {
		if containsSAN(domains, sanName) {
			// Duplicate; skip this name
			continue
		}

		// Name is unique
		domains = append(domains, sanName)
	}

	return domains
}

// ObtainForCSR tries to obtain a certificate matching the CSR passed into it.
//
// The domains are inferred from the SubjectAltNames, if any.
// The private key for this CSR is not required.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
//
// This function will never return a partial certificate.
// If one domain in the list fails, the whole certificate will fail.
func (c *Certifier) ObtainForCSR(csr x509.CertificateRequest, bundle bool) (*certificate.Resource, error) {
	// figure out what domains it concerns
	// start with the common name
	domains := extractDomainsCSR(&csr)

	if bundle {
		log.Infof("[%s] acme: Obtaining bundled SAN certificate given a CSR", strings.Join(domains, ", "))
	} else {
		log.Infof("[%s] acme: Obtaining SAN certificate given a CSR", strings.Join(domains, ", "))
	}

	order, err := c.core.Orders.New(domains)
	if err != nil {
		return nil, err
	}

	authz, err := c.getAuthorizations(order)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		c.deactivateAuthorizations(order)
		return nil, err
	}

	err = c.resolver.Solve(authz)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		c.deactivateAuthorizations(order)
		return nil, err
	}

	log.Infof("[%s] acme: Validations succeeded; requesting certificates", strings.Join(domains, ", "))

	failures := make(obtainError)
	cert, err := c.getForCSR(domains, order, bundle, csr.Raw, nil)
	if err != nil {
		for _, auth := range authz {
			failures[challenge.GetTargetedDomain(auth)] = err
		}
	}

	if cert != nil {
		// Add the CSR to the certificate so that it can be used for renewals.
		cert.CSR = certcrypto.PEMEncode(&csr)
	}

	// Do not return an empty failures map,
	// because it would still be a non-nil error value
	if len(failures) > 0 {
		return cert, failures
	}
	return cert, nil
}

func (c *Certifier) getForCSR(domains []string, order acme.ExtendedOrder, bundle bool, csr []byte, privateKeyPem []byte) (*certificate.Resource, error) {
	respOrder, err := c.core.Orders.UpdateForCSR(order.Finalize, csr)
	if err != nil {
		return nil, err
	}

	commonName := domains[0]
	certRes := &certificate.Resource{
		Domain:     commonName,
		CertURL:    respOrder.Certificate,
		PrivateKey: privateKeyPem,
	}

	if respOrder.Status == acme.StatusValid {
		// if the certificate is available right away, short cut!
		ok, errR := c.checkResponse(respOrder, certRes, bundle)
		if errR != nil {
			return nil, errR
		}

		if ok {
			return certRes, nil
		}
	}

	timeout := c.options.Timeout
	if c.options.Timeout <= 0 {
		timeout = 30 * time.Second
	}

	err = wait.For("certificate", timeout, timeout/60, func() (bool, error) {
		ord, errW := c.core.Orders.Get(order.Location)
		if errW != nil {
			return false, errW
		}

		done, errW := c.checkResponse(ord, certRes, bundle)
		if errW != nil {
			return false, errW
		}

		return done, nil
	})

	return certRes, err
}

// checkResponse checks to see if the certificate is ready and a link is contained in the response.
//
// If so, loads it into certRes and returns true.
// If the cert is not yet ready, it returns false.
//
// The certRes input should already have the Domain (common name) field populated.
//
// If bundle is true, the certificate will be bundled with the issuer's cert.
func (c *Certifier) checkResponse(order acme.Order, certRes *certificate.Resource, bundle bool) (bool, error) {
	valid, err := checkOrderStatus(order)
	if err != nil || !valid {
		return valid, err
	}

	cert, issuer, err := c.core.Certificates.Get(order.Certificate, bundle)
	if err != nil {
		return false, err
	}

	log.Infof("[%s] Server responded with a certificate.", certRes.Domain)

	certRes.IssuerCertificate = issuer
	certRes.Certificate = cert
	certRes.CertURL = order.Certificate
	certRes.CertStableURL = order.Certificate

	return true, nil
}

// Revoke takes a PEM encoded certificate or bundle and tries to revoke it at the CA.
func (c *Certifier) Revoke(cert []byte) error {
	return c.certifier.Revoke(cert)
}

// Renew takes a Resource and tries to renew the certificate.
//
// If the renewal process succeeds, the new certificate will ge returned in a new CertResource.
// Please be aware that this function will return a new certificate in ANY case that is not an error.
// If the server does not provide us with a new cert on a GET request to the CertURL
// this function will start a new-cert flow where a new certificate gets generated.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
//
// For private key reuse the PrivateKey property of the passed in Resource should be non-nil.
func (c *Certifier) Renew(certRes certificate.Resource, bundle, mustStaple bool) (*certificate.Resource, error) {
	// Input certificate is PEM encoded.
	// Decode it here as we may need the decoded cert later on in the renewal process.
	// The input may be a bundle or a single certificate.
	certificates, err := certcrypto.ParsePEMBundle(certRes.Certificate)
	if err != nil {
		return nil, err
	}

	x509Cert := certificates[0]
	if x509Cert.IsCA {
		return nil, fmt.Errorf("[%s] Certificate bundle starts with a CA certificate", certRes.Domain)
	}

	// This is just meant to be informal for the user.
	timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
	log.Infof("[%s] acme: Trying renewal with %d hours remaining", certRes.Domain, int(timeLeft.Hours()))

	// We always need to request a new certificate to renew.
	// Start by checking to see if the certificate was based off a CSR,
	// and use that if it's defined.
	if len(certRes.CSR) > 0 {
		csr, errP := certcrypto.PemDecodeTox509CSR(certRes.CSR)
		if errP != nil {
			return nil, errP
		}

		return c.ObtainForCSR(*csr, bundle)
	}

	var privateKey crypto.PrivateKey
	if certRes.PrivateKey != nil {
		privateKey, err = certcrypto.ParsePEMPrivateKey(certRes.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	query := certificate.ObtainRequest{
		Domains:    certcrypto.ExtractDomains(x509Cert),
		Bundle:     bundle,
		PrivateKey: privateKey,
		MustStaple: mustStaple,
	}
	return c.Obtain(query)
}

// GetOCSP takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any.
//
// The returned []byte can be passed directly into the OCSPStaple property of a tls.Certificate.
// If the bundle only contains the issued certificate,
// this function will try to get the issuer certificate from the IssuingCertificateURL in the certificate.
//
// If the []byte and/or ocsp.Response return values are nil, the OCSP status may be assumed OCSPUnknown.
func (c *Certifier) GetOCSP(bundle []byte) ([]byte, *ocsp.Response, error) {
	return c.certifier.GetOCSP(bundle)
}

// Get attempts to fetch the certificate at the supplied URL.
// The URL is the same as what would normally be supplied at the Resource's CertURL.
//
// The returned Resource will not have the PrivateKey and CSR fields populated as these will not be available.
//
// If bundle is true, the Certificate field in the returned Resource includes the issuer certificate.
func (c *Certifier) Get(url string, bundle bool) (*certificate.Resource, error) {
	return c.certifier.Get(url, bundle)
}

func checkOrderStatus(order acme.Order) (bool, error) {
	switch order.Status {
	case acme.StatusValid:
		return true, nil
	case acme.StatusInvalid:
		return false, order.Error
	default:
		return false, nil
	}
}
